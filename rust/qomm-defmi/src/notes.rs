//! Balances that do not sit at an address.
//!
//! A holding is a note `C = g^S · A_a^v · h^r`. The recipient, not the sender,
//! controls the serial: an address is `(A, B) = (g^a, g^b)`, a sender draws an
//! ephemeral `e`, publishes `E = g^e`, and builds against `g^{H(A^e)}·B`. That
//! point is computable from public data but `S = H(A^e) + b` is not, so a
//! sender can address a note it cannot spend.
//!
//! Spending publishes `g^S` --- never the scalar, which would hand the sender
//! the payee's long-term spend key --- with a proof that it is a bare power of
//! the base point, and a one-out-of-many proof that some note in a ring
//! satisfies `C_i / (g^S · C') = h^*`. Without the bare-power proof the serial
//! could be published as `g^S h^u` for any known u, giving a fresh nullifier
//! every time and making double spending free.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use qomm_zk::oneofmany::{self, GkProof};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::{opening_terms, prove_opening, Batch, OpeningProof, TranscriptExt};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::collections::HashSet;

fn scalar_from(label: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"qomm:defmi:note:v1:");
    hasher.update(label);
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

#[derive(Clone, Copy)]
pub struct Address { pub view: RistrettoPoint, pub spend: RistrettoPoint }

/// The two secrets behind an address, split because they do different jobs: the
/// view key finds your own notes and could be handed to an auditor, while only
/// the spend key turns a note into a serial number.
pub struct Wallet { view: Scalar, spend: Scalar, pub address: Address }

impl Wallet {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let view = Scalar::random(rng);
        let spend = Scalar::random(rng);
        Wallet { view, spend, address: Address { view: G * view, spend: G * spend } }
    }
    fn shared(&self, ephemeral: &RistrettoPoint) -> Scalar {
        scalar_from(b"shared", &[(ephemeral * self.view).compress().as_bytes()])
    }
    pub fn serial(&self, ephemeral: &RistrettoPoint) -> Scalar {
        self.shared(ephemeral) + self.spend
    }
}

/// What lands on the ledger. The one-time point is published separately so a
/// settlement can check that a note carries the value commitment its proof is
/// about; folded together, that check has nothing to compare.
#[derive(Clone)]
pub struct Note {
    pub one_time: RistrettoPoint,
    pub value_commitment: RistrettoPoint,
    pub ephemeral: RistrettoPoint,
    pub masked_value: Scalar,
    pub masked_blinding: Scalar,
}

#[derive(Clone, Copy)]
pub struct Opening { pub value: u64, pub blinding: Scalar, pub serial: Scalar }

/// Knowledge of the discrete log of the published serial point.
pub struct SerialProof { pub t: RistrettoPoint, pub z: Scalar }

/// What a spend hands back: the proof that goes on the wire, the notes that go
/// into the pool, and the blindings the payer keeps.
pub struct Spend {
    pub proof: SpendProof,
    pub notes: Vec<Note>,
    /// One per output, against the asset tag the leg was proved under.
    pub tagged_blindings: Vec<Scalar>,
}

pub struct SpendProof {
    pub serial_point: RistrettoPoint,
    pub serial_proof: SerialProof,
    pub pseudo: RistrettoPoint,
    pub ring: GkProof,
    pub outputs: Vec<RistrettoPoint>,
    pub output_range: RangeProof,
    pub output_range_commitments: Vec<CompressedRistretto>,
    pub balance: OpeningProof,
    pub tag: RistrettoPoint,
}

pub struct NoteLedger {
    pub key: Pedersen,
    pub bits: usize,
    gens: BulletproofGens,
    pub notes: Vec<Note>,
    spent: HashSet<[u8; 32]>,
    /// The state root, kept rather than recomputed. See `snapshot`.
    rolling: sha2::Sha256,
}

impl NoteLedger {
    pub fn new(key: Pedersen, bits: usize) -> Self {
        let mut rolling = sha2::Sha256::new();
        rolling.update(b"QOMM:DEFMI:NOTES:v1");
        NoteLedger { gens: BulletproofGens::new(bits, 2), key, bits,
                     notes: Vec::new(), spent: HashSet::new(), rolling }
    }

    fn masks(&self, shared: &Scalar) -> (Scalar, Scalar) {
        let encoded = shared.to_bytes();
        (scalar_from(b"mask:value", &[&encoded]), scalar_from(b"mask:blinding", &[&encoded]))
    }

    fn one_time_point(&self, address: &Address, shared: &Scalar) -> RistrettoPoint {
        G * shared + address.spend
    }

    /// Run by the sender. `value_commitment` lets a spend hand in a commitment
    /// already made under a blinded tag; the note still has to be openable
    /// under the bare asset generator, so `effective_blinding` is the exponent
    /// of h in that form.
    pub fn build_note<R: RngCore + CryptoRng>(
        &self, address: &Address, value: u64, value_commitment: RistrettoPoint,
        effective_blinding: &Scalar, rng: &mut R,
    ) -> Note {
        let ephemeral_secret = Scalar::random(rng);
        let ephemeral = G * ephemeral_secret;
        let shared = scalar_from(b"shared",
            &[(address.view * ephemeral_secret).compress().as_bytes()]);
        let (mv, mb) = self.masks(&shared);
        Note {
            one_time: self.one_time_point(address, &shared),
            value_commitment,
            ephemeral,
            masked_value: Scalar::from(value) + mv,
            masked_blinding: effective_blinding + mb,
        }
    }

    pub fn commitment_of(&self, note: &Note) -> RistrettoPoint {
        note.one_time + note.value_commitment
    }

    pub fn add(&mut self, note: Note) -> usize {
        self.rolling.update(self.commitment_of(&note).compress().as_bytes());
        self.notes.push(note);
        self.notes.len() - 1
    }

    /// One scalar multiplication per note; no trial decryption of amounts.
    pub fn scan(&self, wallet: &Wallet, asset_key: &Pedersen) -> Vec<(usize, Opening)> {
        let mut found = Vec::new();
        for (index, note) in self.notes.iter().enumerate() {
            let shared = wallet.shared(&note.ephemeral);
            let (mv, mb) = self.masks(&shared);
            let value_scalar = note.masked_value - mv;
            let blinding = note.masked_blinding - mb;
            // recover the value only if it is a small integer
            let Some(value) = small_scalar(&value_scalar, self.bits) else { continue };
            let expected = self.one_time_point(&wallet.address, &shared)
                + asset_key.commit_u64(value, &blinding);
            if expected == self.commitment_of(note) {
                found.push((index, Opening { value, blinding, serial: wallet.serial(&note.ephemeral) }));
            }
        }
        found
    }

    fn serial_transcript(context: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"qomm:note:serial");
        t.append_message(b"ctx", context);
        t
    }
    fn ring_transcript(context: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"qomm:note:ring");
        t.append_message(b"ctx", context);
        t
    }
    fn range_transcript(context: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"qomm:note:range");
        t.append_message(b"ctx", context);
        t
    }
    fn balance_transcript(context: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"qomm:note:balance");
        t.append_message(b"ctx", context);
        t
    }

    fn tagged_context(context: &[u8], tag: &RistrettoPoint) -> Vec<u8> {
        let mut out = context.to_vec();
        out.extend_from_slice(b":tag:");
        out.extend_from_slice(tag.compress().as_bytes());
        out
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_spend<R: RngCore + CryptoRng>(
        &self, ring: &[usize], index: usize, opening: &Opening,
        tag: &RistrettoPoint, gamma: &Scalar,
        outputs: &[(Address, u64)], context: &[u8], rng: &mut R,
    ) -> Result<Spend, &'static str> {
        let position = ring.iter().position(|i| *i == index).ok_or("the ring omits the note")?;
        let total: u64 = outputs.iter().map(|(_, v)| *v).sum();
        if total != opening.value { return Err("outputs do not sum to the note being spent"); }
        let ctx = Self::tagged_context(context, tag);
        let tagged = self.key.with_value_generator(*tag);
        let pc = PedersenGens { B: *tag, B_blinding: self.key.h };

        let serial_point = G * opening.serial;
        let serial_proof = self.prove_serial(&serial_point, &opening.serial, &ctx, rng);

        let pseudo_blinding = Scalar::random(rng);
        let pseudo = tagged.commit_u64(opening.value, &pseudo_blinding);
        let pseudo_effective = gamma * Scalar::from(opening.value) + pseudo_blinding;

        let offset = serial_point + pseudo;
        let members: Vec<RistrettoPoint> = ring.iter()
            .map(|i| self.commitment_of(&self.notes[*i]) - offset).collect();
        let ring_proof = oneofmany::prove(&self.key, &mut Self::ring_transcript(&ctx),
                                          &members, position,
                                          &(opening.blinding - pseudo_effective), rng)?;

        let values: Vec<u64> = outputs.iter().map(|(_, v)| *v).collect();
        let blindings: Vec<Scalar> = outputs.iter().map(|_| Scalar::random(rng)).collect();
        let (output_range, output_range_commitments) = RangeProof::prove_multiple(
            &self.gens, &pc, &mut Self::range_transcript(&ctx), &values, &blindings, self.bits)
            .map_err(|_| "an output is not in range")?;

        let mut notes = Vec::with_capacity(outputs.len());
        let mut commitments = Vec::with_capacity(outputs.len());
        for ((address, value), blinding) in outputs.iter().zip(blindings.iter()) {
            let commitment = tagged.commit_u64(*value, blinding);
            notes.push(self.build_note(address, *value, commitment,
                                       &(gamma * Scalar::from(*value) + blinding), rng));
            commitments.push(commitment);
        }
        let residual = pseudo - commitments.iter().sum::<RistrettoPoint>();
        let tagged_sum: Scalar = blindings.iter().sum();
        let balance = prove_opening(&self.key, &mut Self::balance_transcript(&ctx),
                                    &residual, &Scalar::ZERO,
                                    &(pseudo_blinding - tagged_sum), rng);
        Ok(Spend {
            proof: SpendProof {
                serial_point, serial_proof, pseudo, ring: ring_proof,
                outputs: commitments, output_range, output_range_commitments,
                balance, tag: *tag,
            },
            notes,
            // Against the tag, not against the bare generator: a settlement
            // that links an output to an instruction needs the blinding the
            // output's own commitment was made with, and taking the bare one
            // is how a tagged leg silently stops verifying.
            tagged_blindings: blindings,
        })
    }

    fn prove_serial<R: RngCore + CryptoRng>(
        &self, point: &RistrettoPoint, serial: &Scalar, context: &[u8], rng: &mut R,
    ) -> SerialProof {
        let witness = Scalar::random(rng);
        let t = G * witness;
        let mut transcript = Self::serial_transcript(context);
        transcript.append_point(b"N", point);
        transcript.append_point(b"T", &t);
        let c = transcript.challenge_scalar(b"c");
        SerialProof { t, z: witness + c * serial }
    }

    fn check_serial(&self, point: &RistrettoPoint, proof: &SerialProof, context: &[u8]) -> bool {
        let mut transcript = Self::serial_transcript(context);
        transcript.append_point(b"N", point);
        transcript.append_point(b"T", &proof.t);
        let c = transcript.challenge_scalar(b"c");
        G * proof.z == proof.t + point * c
    }

    pub fn check_spend<R: RngCore + CryptoRng>(
        &self, ring: &[usize], proof: &SpendProof, context: &[u8], rng: &mut R,
    ) -> Result<(), &'static str> {
        let key = proof.serial_point.compress().to_bytes();
        if self.spent.contains(&key) { return Err("serial already spent"); }
        let ctx = Self::tagged_context(context, &proof.tag);
        if !self.check_serial(&proof.serial_point, &proof.serial_proof, &ctx) {
            return Err("the serial is not a bare power of the base point");
        }
        if ring.iter().any(|i| *i >= self.notes.len()) { return Err("the ring names an absent note"); }
        let unique: HashSet<_> = ring.iter().collect();
        if unique.len() != ring.len() { return Err("the ring repeats a note"); }

        let offset = proof.serial_point + proof.pseudo;
        let members: Vec<RistrettoPoint> = ring.iter()
            .map(|i| self.commitment_of(&self.notes[*i]) - offset).collect();
        if !oneofmany::verify(&self.key, &mut Self::ring_transcript(&ctx), &members, &proof.ring) {
            return Err("no note in the ring carries this serial");
        }

        let pc = PedersenGens { B: proof.tag, B_blinding: self.key.h };
        if proof.output_range_commitments.len() != proof.outputs.len()
            || proof.output_range_commitments.iter().zip(proof.outputs.iter())
                .any(|(c, o)| *c != o.compress())
        {
            return Err("the range proof is about other outputs");
        }
        proof.output_range
            .verify_multiple(&self.gens, &pc, &mut Self::range_transcript(&ctx),
                             &proof.output_range_commitments, self.bits)
            .map_err(|_| "an output is not shown to be in range")?;

        let residual = proof.pseudo - proof.outputs.iter().sum::<RistrettoPoint>();
        let mut batch = Batch::new();
        let (s, p) = opening_terms(&self.key, &mut Self::balance_transcript(&ctx),
                                   &residual, &proof.balance, &Batch::weight(rng));
        batch.push(s, p);
        if !batch.verify() { return Err("outputs do not add up to the note being spent"); }
        Ok(())
    }

    pub fn apply_spend(&mut self, proof: &SpendProof, notes: Vec<Note>) -> Result<(), &'static str> {
        let key = proof.serial_point.compress().to_bytes();
        if !self.spent.insert(key) { return Err("serial already spent"); }
        self.rolling.update(b"s");
        self.rolling.update(key);
        // spent notes stay in the pool: removing them would say which one went
        for note in notes { self.add(note); }
        Ok(())
    }

    /// The state root, in constant time.
    ///
    /// This used to walk the whole ledger --- compressing every note that had
    /// ever existed and re-sorting every spent serial --- and a settlement
    /// takes four of them, two rails before and after. `benches/rings.rs`
    /// measured what that costs: 4.3 us a note, so 17.7 ms of root against
    /// 8 ms of cryptography at a thousand notes, and 93.5 ms against the same
    /// 8 ms at four thousand. A settlement cost proportional to total history
    /// is the one thing the account rail was careful not to have.
    ///
    /// Nothing about the ledger required it. Notes are only ever appended ---
    /// spent ones stay in the pool, because removing one would say which it
    /// was --- and serials are only ever inserted, so the hash of the whole
    /// history is a running hash extended once per change. The sort was buying
    /// order-independence for a sequence that already has an order: the one
    /// the chain applied.
    pub fn snapshot(&self) -> [u8; 32] {
        self.rolling.clone().finalize().into()
    }
}

/// Recover a small integer from a scalar, or nothing.
fn small_scalar(scalar: &Scalar, bits: usize) -> Option<u64> {
    let bytes = scalar.to_bytes();
    if bytes[8..].iter().any(|b| *b != 0) { return None; }
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[..8]);
    let value = u64::from_le_bytes(value);
    if bits < 64 && value >= (1u64 << bits) { return None; }
    Some(value)
}

/// Decoys drawn from the newest `window` notes, with the real note inside.
///
/// `ring_for` draws uniformly over the whole pool, and that is only an
/// anonymity set if a real spend is uniform over the whole pool too. It is not:
/// a settlement pays with a note it was paid, so the spent note is recent, and
/// a uniform decoy usually is not. An observer that guesses the newest member
/// of the ring then wins far more often than one over the ring size ---
/// `benches/rings.rs` measures how much more.
///
/// The fix is to draw the decoys from where the real ones come from. `window`
/// is how far back that is, in notes; a pool shorter than the window falls back
/// to the whole pool, which is the same thing when there is no history to
/// stand out against.
pub fn ring_recent(pool: usize, index: usize, size: usize, window: usize, seed: u64)
    -> Result<Vec<usize>, &'static str> {
    if size < 2 || !size.is_power_of_two() { return Err("ring size must be a power of two, at least two"); }
    if pool < size { return Err("the pool is smaller than the ring"); }
    if index >= pool { return Err("the note is not in the pool"); }
    // The window has to hold the ring, and it has to reach back far enough to
    // cover the real note --- a window that excluded it would name it outright.
    let span = window.max(size).max(pool - index);
    let span = span.min(pool);
    let floor = pool - span;
    let mut ring: Vec<usize> = Vec::with_capacity(size);
    ring.push(index);
    let mut state = seed | 1;
    while ring.len() < size {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let candidate = floor + (state >> 33) as usize % span;
        if !ring.contains(&candidate) { ring.push(candidate); }
    }
    for i in (1..ring.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ring.swap(i, (state >> 33) as usize % (i + 1));
    }
    Ok(ring)
}

/// Decoys drawn from the pool, with the real note somewhere inside.
pub fn ring_for(pool: usize, index: usize, size: usize, seed: u64) -> Result<Vec<usize>, &'static str> {
    if size < 2 || !size.is_power_of_two() { return Err("ring size must be a power of two, at least two"); }
    if pool < size { return Err("the pool is smaller than the ring"); }
    let mut ring: Vec<usize> = Vec::with_capacity(size);
    ring.push(index);
    let mut state = seed | 1;
    while ring.len() < size {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let candidate = (state >> 33) as usize % pool;
        if !ring.contains(&candidate) { ring.push(candidate); }
    }
    // deterministic shuffle, so the real note is not always first
    for i in (1..ring.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ring.swap(i, (state >> 33) as usize % (i + 1));
    }
    let _ = RistrettoPoint::identity();
    Ok(ring)
}
