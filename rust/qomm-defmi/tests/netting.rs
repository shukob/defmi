//! Netting cycles, and the trade each mode makes.
//!
//! The behavioural distinction is admissibility: a gross rail refuses an order
//! it cannot cover now, a net rail waits until the close. The pair of tests
//! around that is the point of the file.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::credit::CreditCtx;
use qomm_defmi::netting::*;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{deal_quorum, frost, Bounds, Issuer, Venue};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

const BITS: usize = 32;

struct Holder { securities: (i64, Scalar), cash: (i64, Scalar) }

struct Fixture {
    key: Pedersen,
    cycle: Cycle,
    issuer: Issuer,
    shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
    holders: BTreeMap<Vec<u8>, Holder>,
    credit: CreditCtx,
}

fn fixture(rng: &mut OsRng, mode: Mode, attest: bool, participants: usize,
           securities: &[(usize, i64)]) -> Fixture {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (sec_tag, _) = registry.blind(3, false, rng).unwrap();
    let (cash_tag, _) = registry.blind(0, false, rng).unwrap();
    let mut sec_book = PositionBook::new(key.clone(), sec_tag, mode.securities_net(),
                                         "securities", BITS);
    let mut cash_book = PositionBook::new(key.clone(), cash_tag, mode.cash_net(), "cash", BITS);
    let mut holders = BTreeMap::new();
    for i in 0..participants {
        let handle = format!("p{i}").into_bytes();
        let opening = securities.iter().find(|(j, _)| *j == i).map(|(_, v)| *v).unwrap_or(10_000);
        let holder = Holder {
            securities: (opening, Scalar::random(rng)),
            cash: (10_000_000, Scalar::random(rng)),
        };
        sec_book.open(&handle, sec_book.tagged()
            .commit(&signed(holder.securities.0), &holder.securities.1));
        cash_book.open(&handle, cash_book.tagged()
            .commit(&signed(holder.cash.0), &holder.cash.1));
        holders.insert(handle, holder);
    }
    let (secret, public) = deal_quorum(7, 3, rng).unwrap();
    let shares = secret.into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap())).collect();
    let venue = Venue::new(key.clone(), &Bounds::default(), public.clone());
    Fixture {
        credit: CreditCtx::new(key.clone(), 64),
        issuer: Issuer::new(key.clone(), Bounds::default()),
        cycle: Cycle::new(key.clone(), mode, sec_book, cash_book, venue, attest).unwrap(),
        key, shares, public, holders,
    }
}

fn signed(value: i64) -> Scalar {
    if value >= 0 { Scalar::from(value as u64) } else { -Scalar::from((-value) as u64) }
}

fn sign(f: &Fixture, message: &[u8], rng: &mut OsRng) -> frost::Signature {
    let chosen: Vec<_> = f.shares.keys().take(3).cloned().collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &chosen {
        let (n, c) = frost::round1::commit(f.shares[id].signing_share(), rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let package = frost::SigningPackage::new(commitments, message);
    let mut sig_shares = BTreeMap::new();
    for id in &chosen {
        sig_shares.insert(*id, frost::round2::sign(&package, &nonces[id], &f.shares[id]).unwrap());
    }
    frost::aggregate(&package, &sig_shares, &f.public).unwrap()
}

/// Returns the order and the two delta blindings, which the counterparties have
/// to carry forward: a position is only usable by whoever knows its blinding.
#[allow(clippy::too_many_arguments)]
fn order(f: &Fixture, seller: &[u8], buyer: &[u8], quantity: u64, price: u64,
         nonce: u8, sec_cap: u64, sec_cap_blinding: Scalar, rng: &mut OsRng)
    -> Result<(Order, Scalar, Scalar), &'static str> {
    let (digest, openings, partial) = f.issuer.build(
        quantity, price, 3,
        RistrettoPoint::mul_base(&Scalar::from(11u64)),
        RistrettoPoint::mul_base(&Scalar::from(22u64)),
        1_500, [nonce; 32], 1_599_845, rng)?;
    let instruction = partial.sealed(sign(f, &digest, rng));
    let value = quantity * price;
    let cash_blinding = Scalar::random(rng);
    let cash_reference = f.key.commit_u64(value, &cash_blinding);
    let value_proof = prove_cash_reference(
        &f.key, &instruction.price_commitment, price, &openings.price,
        quantity, &openings.amount, &cash_blinding, rng);

    let sold = &f.holders[seller];
    let bought = &f.holders[buyer];
    let sec_delta = Scalar::random(rng);
    let cash_delta = Scalar::random(rng);
    let sec_leg = f.cycle.securities.build_leg(
        seller, buyer, quantity, &sec_delta,
        sold.securities.0, &sold.securities.1,
        &instruction.amount_commitment, &openings.amount,
        sec_cap, &sec_cap_blinding, rng)?;
    let cash_leg = f.cycle.cash.build_leg(
        buyer, seller, value, &cash_delta,
        bought.cash.0, &bought.cash.1,
        &cash_reference, &cash_blinding, 0, &Scalar::ZERO, rng)?;
    Ok((Order { instruction, securities: sec_leg, cash: cash_leg, cash_reference, value_proof },
        sec_delta, cash_delta))
}

/// Both sides update their own books, which the cycle never sees.
fn settle_books(f: &mut Fixture, seller: &[u8], buyer: &[u8], quantity: u64, value: u64,
                sec_delta: Scalar, cash_delta: Scalar) {
    {
        let s = f.holders.get_mut(&seller.to_vec()).unwrap();
        s.securities.0 -= quantity as i64;
        s.securities.1 -= sec_delta;
        s.cash.0 += value as i64;
        s.cash.1 += cash_delta;
    }
    let b = f.holders.get_mut(&buyer.to_vec()).unwrap();
    b.securities.0 += quantity as i64;
    b.securities.1 += sec_delta;
    b.cash.0 -= value as i64;
    b.cash.1 -= cash_delta;
}

#[test]
fn every_mode_settles_and_conserves() {
    let mut rng = OsRng;
    for (mode, attest) in [(Mode::GrossGross, false), (Mode::GrossNet, false),
                           (Mode::NetNet, false), (Mode::NetNet, true)] {
        let mut f = fixture(&mut rng, mode, attest, 4, &[]);
        for nonce in 0..4u8 {
            let (o, sd, cd) = order(&f, b"p0", b"p1", 40, 10_000, nonce, 0,
                                    Scalar::ZERO, &mut rng).expect("build");
            f.cycle.admit(&o, 1_000, &mut rng).expect("admit");
            settle_books(&mut f, b"p0", b"p1", 40, 40 * 10_000, sd, cd);
        }
        assert!(f.cycle.securities.conserved() && f.cycle.cash.conserved(),
                "{mode:?} attest={attest}");
    }
}

#[test]
fn a_gross_rail_refuses_a_delivery_it_cannot_cover_yet() {
    // settlement cannot fail, but the order cannot exist
    let mut rng = OsRng;
    let f = fixture(&mut rng, Mode::GrossGross, false, 3, &[(0, 0)]);
    assert_eq!(
        order(&f, b"p0", b"p2", 100, 10_000, 1, 0, Scalar::ZERO, &mut rng).err(),
        Some("the order would leave the position short of its cap"));
}

#[test]
fn a_net_rail_lets_the_offsetting_pair_through_in_either_order() {
    // and this is what the trade buys back: order-insensitivity
    let mut rng = OsRng;
    for delivery_first in [true, false] {
        let mut f = fixture(&mut rng, Mode::NetNet, false, 3, &[(0, 0)]);
        let mut pairs: Vec<(&[u8], &[u8])> = vec![(b"p0", b"p2"), (b"p1", b"p0")];
        if !delivery_first { pairs.reverse(); }
        for (nonce, (seller, buyer)) in pairs.into_iter().enumerate() {
            let (o, sd, cd) = order(&f, seller, buyer, 100, 10_000, nonce as u8, 0,
                                    Scalar::ZERO, &mut rng).expect("build");
            f.cycle.admit(&o, 1_000, &mut rng).expect("admit");
            settle_books(&mut f, seller, buyer, 100, 100 * 10_000, sd, cd);
        }
        let coverage: Vec<_> = f.holders.iter()
            .map(|(h, holder)| f.cycle.securities
                .build_coverage(h, holder.securities.0, &holder.securities.1, 0, &Scalar::ZERO)
                .expect("coverage"))
            .collect();
        let cash: Vec<_> = f.holders.iter()
            .map(|(h, holder)| f.cycle.cash
                .build_coverage(h, holder.cash.0, &holder.cash.1, 0, &Scalar::ZERO)
                .expect("cash coverage"))
            .collect();
        assert_eq!(f.cycle.close(&coverage, &cash, None), Ok(()));
    }
}

#[test]
fn a_cap_lets_a_net_position_go_below_zero_and_no_further() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::NetNet, false, 3, &[(0, 0)]);
    let cap = 300u64;
    let cap_blinding = Scalar::random(&mut rng);
    // granted under the rail's own key: a cap in other units is incomparable
    let rail_credit = CreditCtx::new(f.cycle.securities.tagged(), 64);
    let line = rail_credit.grant(b"p0", "securities", cap, &cap_blinding,
                                 10_000, &Scalar::random(&mut rng), 500).unwrap();
    f.cycle.securities.grant(&rail_credit, line).expect("grant");

    // the buyer pays out of a finite cash position, so the trade has to fit it
    let (o, sd, cd) = order(&f, b"p0", b"p2", 200, 10_000, 1, 0, Scalar::ZERO,
                            &mut rng).unwrap();
    f.cycle.admit(&o, 1_000, &mut rng).expect("admit");
    settle_books(&mut f, b"p0", b"p2", 200, 200 * 10_000, sd, cd);
    assert_eq!(f.holders[&b"p0".to_vec()].securities.0, -200);

    let coverage: Vec<_> = f.holders.iter()
        .map(|(h, holder)| {
            let (c, cb) = if h == b"p0" { (cap, cap_blinding) } else { (0, Scalar::ZERO) };
            f.cycle.securities
                .build_coverage(h, holder.securities.0, &holder.securities.1, c, &cb)
                .expect("coverage")
        })
        .collect();
    let cash: Vec<_> = f.holders.iter()
        .map(|(h, holder)| f.cycle.cash
            .build_coverage(h, holder.cash.0, &holder.cash.1, 0, &Scalar::ZERO).unwrap())
        .collect();
    assert_eq!(f.cycle.close(&coverage, &cash, None), Ok(()));
}

#[test]
fn a_position_beyond_its_cap_fails_at_the_close() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::NetNet, false, 3, &[(0, 0)]);
    let cap_blinding = Scalar::random(&mut rng);
    let rail_credit = CreditCtx::new(f.cycle.securities.tagged(), 64);
    let line = rail_credit.grant(b"p0", "securities", 300, &cap_blinding,
                                 10_000, &Scalar::random(&mut rng), 500).unwrap();
    f.cycle.securities.grant(&rail_credit, line).unwrap();
    let (o, _, _) = order(&f, b"p0", b"p2", 400, 10_000, 1, 0, Scalar::ZERO,
                          &mut rng).unwrap();
    f.cycle.admit(&o, 1_000, &mut rng).unwrap();
    assert!(f.cycle.securities
        .build_coverage(b"p0", -400, &f.holders[&b"p0".to_vec()].securities.1,
                        300, &cap_blinding)
        .is_err());
}

#[test]
fn a_leg_cannot_pay_itself() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::NetNet, false, 3, &[]);
    let (mut o, _, _) = order(&f, b"p0", b"p1", 40, 100_000, 1, 0, Scalar::ZERO,
                              &mut rng).unwrap();
    o.securities.payee = o.securities.payer.clone();
    assert_eq!(f.cycle.admit(&o, 1_000, &mut rng), Err("a leg cannot pay itself"));
}

#[test]
fn an_instruction_settles_once_per_cycle() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::GrossGross, false, 3, &[]);
    let (o, _, _) = order(&f, b"p0", b"p1", 40, 100_000, 1, 0, Scalar::ZERO,
                          &mut rng).unwrap();
    assert_eq!(f.cycle.admit(&o, 1_000, &mut rng), Ok(()));
    assert_eq!(f.cycle.admit(&o, 1_000, &mut rng), Err("already settled"));
}

#[test]
fn a_batch_attestation_only_makes_sense_when_both_rails_net() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (tag, _) = registry.blind(3, false, &mut rng).unwrap();
    let (secret, public) = deal_quorum(7, 3, &mut rng).unwrap();
    drop(secret);
    for mode in [Mode::GrossGross, Mode::GrossNet] {
        let books = || PositionBook::new(key.clone(), tag.clone(), false, "securities", BITS);
        let venue = Venue::new(key.clone(), &Bounds::default(), public.clone());
        assert!(Cycle::new(key.clone(), mode, books(), books(), venue, true).is_err());
    }
}

#[test]
fn an_attestation_for_other_positions_is_refused() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::NetNet, true, 3, &[]);
    let (o, sd, cd) = order(&f, b"p0", b"p1", 40, 10_000, 1, 0, Scalar::ZERO,
                            &mut rng).unwrap();
    f.cycle.admit(&o, 1_000, &mut rng).unwrap();
    settle_books(&mut f, b"p0", b"p1", 40, 40 * 10_000, sd, cd);
    let coverage: Vec<_> = f.holders.iter()
        .map(|(h, holder)| f.cycle.securities
            .build_coverage(h, holder.securities.0, &holder.securities.1, 0, &Scalar::ZERO))
        .filter_map(|c| c.ok())
        .collect();
    assert_eq!(
        f.cycle.close(&coverage, &[], Some(&BatchAttestation { digest: [0u8; 32] })),
        Err("the attestation is for other positions"));
}
