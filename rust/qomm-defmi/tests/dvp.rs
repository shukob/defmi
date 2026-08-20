//! Delivery versus payment on ledgers that cannot read themselves.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::ledger::Ledger;
use qomm_defmi::settlement::*;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::{Handle, Identity};
use qomm_zkpi::{deal_quorum, frost, Bounds, Instruction, Issuer, Venue};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

const BITS: usize = 32;
const QTY: u64 = 100;
const PRICE: u64 = 99_990;
const SEC_BALANCE: u64 = 5_000;
const CASH_BALANCE: u64 = 50_000_000;

struct World {
    key: Pedersen,
    registry: AssetRegistry,
    defmi: Defmi,
    issuer: Issuer,
    shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
    sec: (u64, Scalar),
    cash: (u64, Scalar),
}


/// The two firms, named the way the design says they should be: one seed each,
/// a handle derived for this venue. The accounts a rail keeps their balances
/// under follow from those handles, so the test cannot open an account the
/// instruction would not name --- which is the property being fixed.
fn seller() -> Handle { Identity::from_seed([11u8; 32]).handle(VENUE) }
fn buyer() -> Handle { Identity::from_seed([22u8; 32]).handle(VENUE) }

const VENUE: &[u8] = b"defmi:test";

fn world(rng: &mut OsRng) -> World {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (secret, public) = deal_quorum(7, 3, rng).unwrap();
    let shares = secret.into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let mut securities = Ledger::new(key.clone(), BITS);
    let mut cash = Ledger::new(key.clone(), BITS);

    let asset_key = key.with_value_generator(registry.tags[3]);
    let sec = (SEC_BALANCE, Scalar::random(rng));
    let cash_holding = (CASH_BALANCE, Scalar::random(rng));
    securities.open(&account_of(&seller().point, SECURITIES_RAIL),
                    asset_key.commit_u64(sec.0, &sec.1));
    securities.open(&account_of(&buyer().point, SECURITIES_RAIL),
                    asset_key.commit_u64(0, &Scalar::random(rng)));
    cash.open(&account_of(&buyer().point, CASH_RAIL),
              key.commit_u64(cash_holding.0, &cash_holding.1));
    cash.open(&account_of(&seller().point, CASH_RAIL),
              key.commit_u64(0, &Scalar::random(rng)));

    let venue = Venue::new(key.clone(), &Bounds::default(), public.clone());
    World {
        issuer: Issuer::new(key.clone(), Bounds::default()),
        defmi: Defmi::new(key.clone(), securities, cash, venue),
        key, registry, shares, public, sec, cash: cash_holding,
    }
}

fn sign(w: &World, message: &[u8], rng: &mut OsRng) -> frost::Signature {
    let chosen: Vec<_> = w.shares.keys().take(3).cloned().collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &chosen {
        let (n, c) = frost::round1::commit(w.shares[id].signing_share(), rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let package = frost::SigningPackage::new(commitments, message);
    let mut shares = BTreeMap::new();
    for id in &chosen {
        shares.insert(*id, frost::round2::sign(&package, &nonces[id], &w.shares[id]).unwrap());
    }
    frost::aggregate(&package, &shares, &w.public).unwrap()
}

fn instruction(w: &World, rng: &mut OsRng, nonce: u8)
    -> (Instruction, InstructionOpenings) {
    let (digest, openings, partial) = w.issuer.build(
        QTY, PRICE, 3,
        buyer().point,      // pays cash, receives securities
        seller().point,     // delivers securities, receives cash
        1_500, [nonce; 32], 1_599_845, rng).unwrap();
    let signature = sign(w, &digest, rng);
    (partial.sealed(signature),
     InstructionOpenings { amount: openings.amount, price: openings.price })
}

fn package(w: &World, rng: &mut OsRng, quantity: u64, price: u64, tag_asset: u32, nonce: u8)
    -> Result<DvpPackage, &'static str> {
    let (instruction, openings) = instruction(w, rng, nonce);
    let (tag, gamma) = w.registry.blind(tag_asset, false, rng).unwrap();
    build_package(
        &w.key, instruction, &w.defmi.securities, &w.defmi.cash,
        quantity, price,
        &Holdings {
            securities_balance: w.sec.0, securities_blinding: w.sec.1,
            cash_balance: w.cash.0, cash_blinding: w.cash.1,
        },
        &openings, Some(&tag), &gamma, rng,
    ).map(|(p, _)| p)
}

#[test]
fn a_valid_delivery_versus_payment_settles() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY, PRICE, 3, 1).unwrap();
    let receipt = w.defmi.settle(&p, 1_000, &mut rng);
    assert_eq!(receipt.status, Ok(()));
    assert!(w.defmi.solvent());
    assert_ne!(receipt.securities_before, receipt.securities_after);
    assert_ne!(receipt.cash_before, receipt.cash_after);
}

#[test]
fn delivering_the_wrong_quantity_is_rejected() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY + 1, PRICE, 3, 2).unwrap();
    assert!(w.defmi.settle(&p, 1_000, &mut rng).status.is_err());
    assert!(w.defmi.solvent());
}

#[test]
fn paying_the_wrong_amount_is_rejected() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY, PRICE - 10, 3, 3).unwrap();
    assert!(w.defmi.settle(&p, 1_000, &mut rng).status.is_err());
}

#[test]
fn nothing_moves_when_a_leg_fails() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let before_sec = w.defmi.securities.snapshot();
    let before_cash = w.defmi.cash.snapshot();
    let p = package(&w, &mut rng, QTY, PRICE + 7, 3, 4).unwrap();
    assert!(w.defmi.settle(&p, 1_000, &mut rng).status.is_err());
    assert_eq!(w.defmi.securities.snapshot(), before_sec);
    assert_eq!(w.defmi.cash.snapshot(), before_cash);
}

#[test]
fn an_instruction_settles_at_most_once() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY, PRICE, 3, 5).unwrap();
    assert_eq!(w.defmi.settle(&p, 1_000, &mut rng).status, Ok(()));
    assert_eq!(w.defmi.settle(&p, 1_000, &mut rng).status, Err("already settled"));
}

#[test]
fn an_expired_instruction_does_not_settle() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY, PRICE, 3, 6).unwrap();
    assert_eq!(w.defmi.settle(&p, 2_000, &mut rng).status, Err("past the deadline"));
}

#[test]
fn a_tag_for_the_wrong_asset_cannot_move_the_balance() {
    // the remainder proof is what binds the disguise to the real asset
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY, PRICE, 7, 7).unwrap();
    assert!(w.defmi.settle(&p, 1_000, &mut rng).status.is_err());
    assert!(w.defmi.solvent());
}

#[test]
fn the_package_looks_the_same_whatever_the_asset() {
    let mut rng = OsRng;
    let mut sizes = std::collections::HashSet::new();
    for (i, asset) in [0u32, 3, 7, 15].iter().enumerate() {
        let key = Pedersen::new(b"qomm:defmi:v1");
        let registry = AssetRegistry::new(key.clone(), 16);
        let mut w = world(&mut rng);
        let asset_key = key.with_value_generator(registry.tags[*asset as usize]);
        let mut securities = Ledger::new(key.clone(), BITS);
        securities.open(&account_of(&seller().point, SECURITIES_RAIL),
                        asset_key.commit_u64(SEC_BALANCE, &w.sec.1));
        securities.open(&account_of(&buyer().point, SECURITIES_RAIL),
                        asset_key.commit_u64(0, &Scalar::random(&mut rng)));
        w.defmi.securities = securities;
        w.registry = registry;
        let p = package(&w, &mut rng, QTY, PRICE, *asset, 20 + i as u8).unwrap();
        assert_eq!(w.defmi.settle(&p, 1_000, &mut rng).status, Ok(()));
        sizes.insert(wire_size(&p));
    }
    assert_eq!(sizes.len(), 1, "the asset leaks through the package size");
}

fn wire_size(p: &DvpPackage) -> usize {
    // compressed points and scalars are 32 bytes each; range proofs report
    // their own length
    let ranges = p.securities_leg.remainder_range.to_bytes().len()
        + p.cash_leg.remainder_range.to_bytes().len()
        + p.instruction.ranges.to_bytes().len();
    let points = 3 /* leg commitments */ + 2 /* tag */ + 3 /* instruction */
        + 2 /* link */ + 2 /* product */ + 2 /* handles */;
    let scalars = 3 /* link */ + 3 /* product */;
    ranges + 32 * (points + scalars) + 64 /* signature */ + 32 /* nonce */
}

#[test]
fn a_stale_range_proof_on_a_bounded_amount_is_refused() {
    let mut rng = OsRng;
    let w = world(&mut rng);
    let (transfer, _) = w.defmi.securities.build_transfer(
        SEC_BALANCE, &w.sec.1, QTY, b"ctx", None, &Scalar::ZERO, false, &mut rng).unwrap();
    assert!(transfer.amount_range.is_some());
    assert_eq!(
        w.defmi.securities.check_transfer(
            &account_of(&seller().point, SECURITIES_RAIL), &transfer, b"ctx", true),
        Err("an externally bounded amount carries a stale range proof"));
}

#[test]
fn issuance_carries_a_proof_that_the_asset_is_listed() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key, 16);
    let (tag, _) = registry.blind(5, true, &mut rng).unwrap();
    assert!(registry.verify_membership(&tag));
    let (bare, _) = registry.blind(5, false, &mut rng).unwrap();
    assert!(!registry.verify_membership(&bare));
    assert!(registry.blind(99, false, &mut rng).is_err());
}

/// A package that arrives over the wire naming other accounts.
///
/// `build_package` derives the four names from the instruction, so an honest
/// caller cannot produce this; it is made by editing a good package, which is
/// what a wire lets anyone do. Before the accounts were derived there was
/// nothing to catch it: the instruction named two group elements, the package
/// named four byte strings, and the two were never compared.
#[test]
fn a_package_cannot_name_accounts_the_instruction_does_not() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let good = package(&w, &mut rng, QTY, PRICE, 3, 1).unwrap();
    assert_eq!(w.defmi.settle(&good, 1_000, &mut rng).status, Ok(()));

    // pay the securities to somebody else
    let mut w = world(&mut rng);
    let mut tampered = package(&w, &mut rng, QTY, PRICE, 3, 2).unwrap();
    let stranger = Identity::from_seed([99u8; 32]).handle(VENUE);
    tampered.securities_to = account_of(&stranger.point, SECURITIES_RAIL);
    assert_eq!(w.defmi.settle(&tampered, 1_000, &mut rng).status,
               Err("the package names accounts the instruction does not"));

    // or take the cash from somebody else
    let mut w = world(&mut rng);
    let mut tampered = package(&w, &mut rng, QTY, PRICE, 3, 3).unwrap();
    tampered.cash_from = account_of(&seller().point, CASH_RAIL);
    assert_eq!(w.defmi.settle(&tampered, 1_000, &mut rng).status,
               Err("the package names accounts the instruction does not"));

    // or run the whole thing backwards
    let mut w = world(&mut rng);
    let mut tampered = package(&w, &mut rng, QTY, PRICE, 3, 4).unwrap();
    std::mem::swap(&mut tampered.cash_from, &mut tampered.cash_to);
    std::mem::swap(&mut tampered.securities_from, &mut tampered.securities_to);
    assert_eq!(w.defmi.settle(&tampered, 1_000, &mut rng).status,
               Err("the package names accounts the instruction does not"));
}

/// Two firms at one venue get different accounts on each rail, and one firm's
/// two rails do not share a name.
#[test]
fn accounts_are_a_function_of_the_handle_and_the_rail() {
    let (a, b) = (seller().point, buyer().point);
    assert_ne!(account_of(&a, SECURITIES_RAIL), account_of(&b, SECURITIES_RAIL));
    assert_ne!(account_of(&a, SECURITIES_RAIL), account_of(&a, CASH_RAIL));
    assert_eq!(account_of(&a, CASH_RAIL), account_of(&a, CASH_RAIL));
}
