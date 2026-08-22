//! Handing an auditor one slice of a wallet, and being honest about what that is.
//!
//! `notes.rs` splits a wallet into a view key and a spend key and says the view
//! key could be handed to an auditor. It could, and that is all it could: the
//! key is one key, so handing it over gives the whole history of that wallet,
//! in every instrument, for every period, permanently. There is no scope and no
//! way back.
//!
//! **The scoping does not go in the key. It goes in the address.** A wallet is
//! a pair of seeds; a scope --- an instrument, a quarter, a mandate --- derives
//! a fresh pair of scalars by hashing, and therefore a fresh address. Notes sent
//! there are found by that scope's view key and by nothing else, and the
//! derivation is one way, so a scope's key says nothing about the seed or about
//! a sibling scope.
//!
//! ```text
//! view_s  = H("view"  || seed_v || scope)      the auditor gets this
//! spend_s = H("spend" || seed_s || scope)      it does not
//! address = (G * view_s, G * spend_s)          both halves are public
//! ```
//!
//! Nothing here is new cryptography, deliberately: the note construction is
//! unchanged, the scan is unchanged, and what changes is which address a payer
//! is told to use. Which means it also works with a counterparty that has
//! already implemented the old thing.
//!
//! # Three things it does not do
//!
//! **A grant cannot be taken back.** Whoever holds a scope's key can read every
//! note ever sent to that address and every one that ever will be. An expiry
//! stops a party that chooses to be stopped and nothing else. What actually
//! revokes is moving to the next scope, because the next scope is a different
//! address --- revocation is address management, not a message.
//!
//! **A view key is incoming only, and closing that is not a matter of effort.**
//! It finds what arrived and cannot see what the wallet spent. The obvious fix
//! --- hand the auditor the serials too --- does not work, and the reason is
//! worth following because it is a property of the construction rather than an
//! omission.
//!
//! Spending a note needs the serial `S` **and** the note's blinding `r`, and a
//! view key recovers `r` by scanning. So a party holding both the view key and
//! the serials can spend, and giving an auditor outflows on top of inflows is
//! giving it the wallet. Verifying an outflow list without the view key is no
//! better: a serial belongs to an address exactly when `S - H(E^a) = b`, and
//! the hash puts that outside what a sigma protocol can prove --- establishing
//! it needs a general-purpose proof system, which this stack deliberately does
//! not use.
//!
//! What is left is [`SpendDisclosure`]: the wallet **signs** what it spent, and
//! anyone can check the signature and check that each serial is in the ledger's
//! spent set. That is attribution, not verification --- a wallet can leave a
//! spend out and nothing here catches it --- and it confers no ability to
//! spend, which is why it is the disclosure that can exist. An auditor holding
//! one of these plus a view key has the wallet, so the two are not meant to go
//! to the same party and `SpendDisclosure` says so where it is built.
//!
//! **Scoping is only as fine as the payers cooperate.** A scope exists because
//! counterparties were told to pay to that address; one who uses last quarter's
//! address puts the note in last quarter's scope and nothing in the protocol
//! stops them. That is an operational control wearing a cryptographic coat, and
//! it is worth knowing which it is.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use qomm_zk::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::notes::{Address, NoteLedger, ViewKey, Wallet};

pub const VIEW_DOMAIN: &[u8] = b"qomm:defmi:view:v1";

/// One scope's scalar. One way, so a scope reveals neither seed nor sibling.
pub fn derive(seed: &[u8], role: &[u8], scope: &str) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(VIEW_DOMAIN);
    hasher.update(b":");
    hasher.update(role);
    hasher.update(b":");
    for part in [seed, scope.as_bytes()] {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

/// One scope handed to one named party, signed by the wallet that owns it.
///
/// The grantee is named and the grant is signed so that a key found somewhere
/// it should not be can be traced to the grant that produced it. That is
/// attribution, not prevention, and it is the same trade the dealt shares make.
pub struct ViewingGrant {
    pub scope: String,
    pub grantee: String,
    pub address: Address,
    pub view_key: ViewKey,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Option<Signature>,
}

impl ViewingGrant {
    pub fn body(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(VIEW_DOMAIN);
        hasher.update(b":grant:");
        for part in [self.scope.as_bytes(), self.grantee.as_bytes()] {
            hasher.update((part.len() as u32).to_be_bytes());
            hasher.update(part);
        }
        hasher.update(self.address.view.compress().as_bytes());
        hasher.update(self.address.spend.compress().as_bytes());
        hasher.update(self.issued_at.to_be_bytes());
        hasher.update(self.expires_at.to_be_bytes());
        hasher.finalize().into()
    }
}

/// A wallet that can hand out one slice of itself at a time.
///
/// The seeds never leave. A scope is derived from them, so the wallet can
/// reproduce any scope it has ever granted --- which is what lets it keep
/// spending notes it has given an auditor the ability to read.
pub struct ScopedWallet {
    view_seed: [u8; 32],
    spend_seed: [u8; 32],
    identity: SigningKey,
}

impl ScopedWallet {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut view_seed = [0u8; 32];
        let mut spend_seed = [0u8; 32];
        rng.fill_bytes(&mut view_seed);
        rng.fill_bytes(&mut spend_seed);
        ScopedWallet { view_seed, spend_seed, identity: SigningKey::generate(rng) }
    }

    pub fn from_seeds(view_seed: [u8; 32], spend_seed: [u8; 32],
                      identity: SigningKey) -> Self {
        ScopedWallet { view_seed, spend_seed, identity }
    }

    pub fn public_identity(&self) -> VerifyingKey {
        self.identity.verifying_key()
    }

    /// The full wallet for one scope. This is what spends.
    pub fn wallet(&self, scope: &str) -> Wallet {
        Wallet::from_parts(derive(&self.view_seed, b"view", scope),
                           derive(&self.spend_seed, b"spend", scope))
    }

    pub fn address(&self, scope: &str) -> Address {
        self.wallet(scope).address
    }

    /// Hand out the ability to read one scope, and sign that it was handed out.
    pub fn grant(&self, scope: &str, grantee: &str, issued_at: u64, days: u64)
        -> ViewingGrant
    {
        let view = derive(&self.view_seed, b"view", scope);
        let spend = derive(&self.spend_seed, b"spend", scope);
        let mut grant = ViewingGrant {
            scope: scope.to_string(), grantee: grantee.to_string(),
            address: Address { view: G * view, spend: G * spend },
            view_key: ViewKey::new(view), issued_at,
            expires_at: issued_at + days * 86_400, signature: None,
        };
        grant.signature = Some(self.identity.sign(&grant.body()));
        grant
    }
}

/// Whether this grant is what it says, and still current.
///
/// Current is a statement about policy and not about capability. A party
/// holding the key can read whatever the key reads whether or not this returns
/// `Ok`; what refusing buys is that a party which *wants* to stay inside its
/// mandate has something to check against, and that a party which does not can
/// be shown to have gone outside it.
pub fn check_grant(grant: &ViewingGrant, owner: &VerifyingKey, now: u64)
    -> Result<(), &'static str>
{
    let signature = grant.signature.as_ref()
        .ok_or("an unsigned grant is a key somebody wrote down")?;
    owner.verify(&grant.body(), signature).map_err(|_| "not signed by that wallet")?;
    if grant.view_key.address_view() != grant.address.view {
        return Err("the key does not open the address it names");
    }
    if now < grant.issued_at {
        return Err("the grant has not begun");
    }
    if now >= grant.expires_at {
        return Err("the grant has expired --- which stops a party that chooses \
                    to be stopped, and nothing else");
    }
    Ok(())
}

/// Every note in the pool addressed to this scope, and their amounts.
pub fn scan_scope(ledger: &NoteLedger, grant: &ViewingGrant, asset_key: &Pedersen)
    -> Vec<(usize, u64, Scalar)>
{
    ledger.scan_view(&grant.view_key, &grant.address, asset_key)
}

/// What the scope holds, for an auditor that has to put a number in a report.
pub fn total_seen(found: &[(usize, u64, Scalar)]) -> u64 {
    found.iter().map(|(_, value, _)| value).sum()
}

/// The commitments for one scope, so an auditor can reconcile it against a
/// figure it was given without opening any single note.
///
/// This is the join between the two modules: a scope is a set of positions, and
/// `reconcile` is what turns a set of positions into agreement with a number.
pub fn scope_commitments(ledger: &NoteLedger, grant: &ViewingGrant,
                         asset_key: &Pedersen)
    -> (Vec<RistrettoPoint>, Vec<Scalar>, u64)
{
    let found = scan_scope(ledger, grant, asset_key);
    let mut commitments = Vec::with_capacity(found.len());
    let mut blindings = Vec::with_capacity(found.len());
    let mut total = 0u64;
    for (_, value, blinding) in &found {
        commitments.push(asset_key.commit_u64(*value, blinding));
        blindings.push(*blinding);
        total += value;
    }
    (commitments, blindings, total)
}


// --- outflows, which are a different disclosure and a weaker one -----------

/// What a wallet says it spent in one scope, signed rather than proved.
///
/// **This does not go to the holder of the scope's view key.** Spending a note
/// needs the serial and the note's blinding, and a view key recovers the
/// blinding by scanning --- so a party with both can spend. The two disclosures
/// are for different parties on purpose, and [`conflicts_with`] is the check
/// that says when they are not.
///
/// What a holder can establish: that this wallet signed this list, and that
/// every serial on it is in the ledger's spent set. What nobody can establish
/// is that the list is complete. A wallet can leave a spend out and the
/// construction cannot tell --- which is the same shape as a clearing house
/// omitting a trade, and is stated in the same place rather than left to be
/// discovered.
pub struct SpendDisclosure {
    pub scope: String,
    pub grantee: String,
    pub serials: Vec<Scalar>,
    pub issued_at: u64,
    pub signature: Option<Signature>,
}

impl SpendDisclosure {
    pub fn body(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(VIEW_DOMAIN);
        hasher.update(b":spent:");
        for part in [self.scope.as_bytes(), self.grantee.as_bytes()] {
            hasher.update((part.len() as u32).to_be_bytes());
            hasher.update(part);
        }
        hasher.update((self.serials.len() as u32).to_be_bytes());
        for serial in &self.serials {
            hasher.update(serial.to_bytes());
        }
        hasher.update(self.issued_at.to_be_bytes());
        hasher.finalize().into()
    }
}

impl ScopedWallet {
    /// Say what one scope spent, and sign it.
    ///
    /// The serials come from the wallet's own scan, so producing this needs the
    /// spend key --- which is the point: nobody else can produce it, and the
    /// signature is what makes it worth anything.
    pub fn disclose_spends(&self, ledger: &NoteLedger, scope: &str, grantee: &str,
                           asset_key: &Pedersen, issued_at: u64) -> SpendDisclosure
    {
        let wallet = self.wallet(scope);
        let serials = ledger.scan(&wallet, asset_key).into_iter()
            .map(|(_, opening)| opening.serial)
            .filter(|serial| ledger.is_spent(serial))
            .collect();
        let mut disclosure = SpendDisclosure {
            scope: scope.to_string(), grantee: grantee.to_string(), serials,
            issued_at, signature: None,
        };
        disclosure.signature = Some(self.identity.sign(&disclosure.body()));
        disclosure
    }

    /// Sign a disclosure somebody assembled by hand. Only the tests need this,
    /// and they need it to say what a *dishonest* disclosure looks like.
    pub fn sign_disclosure(&self, disclosure: &SpendDisclosure) -> Signature {
        self.identity.sign(&disclosure.body())
    }
}

/// That this wallet signed this list, and that the ledger agrees each was spent.
///
/// Completeness is not established and cannot be. The return value says how
/// many serials the ledger has no record of, because a list naming a spend that
/// never happened is a different failure from one that leaves a spend out, and
/// only the first is visible here.
pub fn check_spend_disclosure(disclosure: &SpendDisclosure, owner: &VerifyingKey,
                              ledger: &NoteLedger)
    -> Result<usize, &'static str>
{
    let signature = disclosure.signature.as_ref()
        .ok_or("an unsigned disclosure is a list somebody typed")?;
    owner.verify(&disclosure.body(), signature)
        .map_err(|_| "not signed by that wallet")?;
    let unknown = disclosure.serials.iter()
        .filter(|serial| !ledger.is_spent(serial)).count();
    if unknown > 0 {
        return Err("the list names a spend the ledger has no record of");
    }
    Ok(disclosure.serials.len())
}

/// Whether handing both of these to one party would hand it the wallet.
///
/// It would, whenever they are for the same scope: the view key recovers each
/// note's blinding and the disclosure supplies the serials, and a spend needs
/// exactly those two. Written as a function rather than a warning in a comment
/// because it is the kind of thing an integration does by accident.
pub fn conflicts_with(grant: &ViewingGrant, disclosure: &SpendDisclosure) -> bool {
    grant.scope == disclosure.scope
}
