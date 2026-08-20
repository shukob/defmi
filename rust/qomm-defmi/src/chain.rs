//! The state a settlement contract has to keep, and what each settlement costs it.
//!
//! Verifying a package is the part that was already measured. A chain also has
//! to *hold* something between settlements, agree on it across nodes, and charge
//! for touching it, and none of that follows from the verification cost. Three
//! questions decide whether this is deployable at all.
//!
//! *What must persist.* Four account commitments move per settlement --- two
//! rails, two sides --- plus one nullifier. Everything else in the package is
//! consumed by verification and never stored. So a settlement writes five slots
//! of 32 bytes, whatever the proof sizes are.
//!
//! *Does the nullifier set grow forever.* This is the question that kills naive
//! designs: a set that only ever grows makes state unbounded in total history
//! rather than in activity. It does not grow forever here, because an
//! instruction carries a deadline and a nullifier only has to outlive it. Past
//! that point replaying the instruction fails on the deadline instead, so the
//! entry is redundant and can be dropped. The set is bounded by instructions in
//! flight within one deadline window, not by everything ever settled.
//!
//! *Can nodes agree on it.* The root is a hash over the state in sorted key
//! order, so two nodes that applied the same settlements agree byte for byte
//! regardless of the order they arrived in.
//!
//! What this is not: a contract for a specific chain. The storage interface
//! every WebAssembly chain offers is a key-value map, which is what this is
//! written against, but the metering, the account model and the transaction
//! format are all chain-specific and none of them are decided here.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use sha2::{Digest, Sha256};

pub const STATE_DOMAIN: &[u8] = b"QOMM:CHAIN:STATE:v1";

/// What one settlement asks the chain to store, so it can be metered before it
/// is applied. Reads and writes are counted separately because chains charge
/// them differently, usually by a wide margin.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Delta {
    pub slots_read: usize,
    pub slots_written: usize,
    pub bytes_written: usize,
    pub nullifiers_added: usize,
}

impl Delta {
    pub fn merge(&mut self, other: &Delta) {
        self.slots_read += other.slots_read;
        self.slots_written += other.slots_written;
        self.bytes_written += other.bytes_written;
        self.nullifiers_added += other.nullifiers_added;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Rejected {
    /// The same instruction, settling twice.
    NullifierSeen,
    /// The instruction outlived its deadline; there is nothing to settle.
    Expired { deadline: u64, now: u64 },
    /// A handle the ledger does not carry. Opening accounts is a separate act.
    UnknownAccount,
}

/// The persistent half of a settlement venue.
///
/// Deliberately holds compressed points rather than decompressed ones. A chain
/// stores bytes, and decompression is a cost the verifier pays on the way in;
/// keeping the decompressed form here would measure a machine that does not
/// exist.
#[derive(Debug, Default, Clone)]
pub struct ChainState {
    accounts: BTreeMap<Vec<u8>, [u8; 32]>,
    /// nullifier -> the deadline past which it can be dropped
    nullifiers: BTreeMap<[u8; 32], u64>,
}

impl ChainState {
    pub fn new() -> Self {
        ChainState::default()
    }

    pub fn open(&mut self, handle: &[u8], commitment: RistrettoPoint) -> Delta {
        self.accounts.insert(handle.to_vec(), commitment.compress().to_bytes());
        Delta { slots_read: 0, slots_written: 1, bytes_written: 32, nullifiers_added: 0 }
    }

    pub fn balance(&self, handle: &[u8]) -> Option<RistrettoPoint> {
        self.accounts
            .get(handle)
            .and_then(|raw| CompressedRistretto(*raw).decompress())
    }

    /// Apply one settled instruction: two rails, two sides, one nullifier.
    ///
    /// The caller has already verified the package --- this does the part a
    /// contract does after that, and nothing else. Every rejection here is a
    /// state condition rather than a cryptographic one, which is the division
    /// the whole design rests on.
    #[allow(clippy::too_many_arguments)]
    pub fn settle(
        &mut self,
        nullifier: [u8; 32],
        deadline: u64,
        now: u64,
        moves: &[(&[u8], RistrettoPoint)],
    ) -> Result<Delta, Rejected> {
        if now > deadline {
            return Err(Rejected::Expired { deadline, now });
        }
        if self.nullifiers.contains_key(&nullifier) {
            return Err(Rejected::NullifierSeen);
        }
        for (handle, _) in moves {
            if !self.accounts.contains_key(*handle) {
                return Err(Rejected::UnknownAccount);
            }
        }
        // nothing is written until every check has passed, so a rejected
        // settlement leaves the state exactly as it was
        for (handle, commitment) in moves {
            self.accounts
                .insert(handle.to_vec(), commitment.compress().to_bytes());
        }
        self.nullifiers.insert(nullifier, deadline);
        Ok(Delta {
            slots_read: moves.len() + 1,
            slots_written: moves.len() + 1,
            bytes_written: moves.len() * 32 + 32 + 8,
            nullifiers_added: 1,
        })
    }

    /// Drop nullifiers whose instruction can no longer be settled anyway.
    ///
    /// This is what keeps the state bounded by activity rather than by history.
    /// Safe because an expired instruction is refused on its deadline, so the
    /// entry stops carrying information the moment it could be removed.
    pub fn prune(&mut self, now: u64) -> usize {
        let before = self.nullifiers.len();
        self.nullifiers.retain(|_, deadline| *deadline >= now);
        before - self.nullifiers.len()
    }

    /// A hash over the state in sorted key order.
    ///
    /// Sorted, so two nodes that applied the same settlements in different
    /// orders still agree. Lengths are hashed before the bytes they describe,
    /// so a handle ending in the bytes of the next key cannot be read as a
    /// different state that happens to serialise the same way.
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(STATE_DOMAIN);
        hasher.update((self.accounts.len() as u64).to_be_bytes());
        for (handle, commitment) in &self.accounts {
            hasher.update((handle.len() as u64).to_be_bytes());
            hasher.update(handle);
            hasher.update(commitment);
        }
        hasher.update((self.nullifiers.len() as u64).to_be_bytes());
        for (nullifier, deadline) in &self.nullifiers {
            hasher.update(nullifier);
            hasher.update(deadline.to_be_bytes());
        }
        hasher.finalize().into()
    }

    pub fn accounts(&self) -> usize {
        self.accounts.len()
    }

    pub fn nullifiers(&self) -> usize {
        self.nullifiers.len()
    }

    /// Bytes the chain is holding on this venue's behalf.
    pub fn stored_bytes(&self) -> usize {
        self.accounts.iter().map(|(h, _)| h.len() + 32).sum::<usize>()
            + self.nullifiers.len() * (32 + 8)
    }
}
