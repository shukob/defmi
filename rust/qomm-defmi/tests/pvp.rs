//! Payment versus payment across two ledgers that share no state.

use curve25519_dalek::scalar::Scalar;
use qomm_defmi::ledger::{Ledger, Transfer, TransferSecrets};
use qomm_defmi::pvp::Swap;
use qomm_zk::adaptor;
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;

const BITS: usize = 32;
const YEN: u64 = 1_000_000;
const USD: u64 = 6_500;

/// One ledger holding one currency, with both parties banked on it.
struct Rail { ledger: Ledger, alice_blinding: Scalar, bob_blinding: Scalar }

fn rail(label: &[u8], alice: u64, bob: u64, rng: &mut OsRng) -> Rail {
    let key = Pedersen::new(label);
    let mut ledger = Ledger::new(key.clone(), BITS);
    let (a, b) = (Scalar::random(rng), Scalar::random(rng));
    // `open` records the supply as it goes, so there is nothing else to mint.
    ledger.open(b"alice", key.commit_u64(alice, &a));
    ledger.open(b"bob", key.commit_u64(bob, &b));
    Rail { ledger, alice_blinding: a, bob_blinding: b }
}

fn transfer(rail: &Rail, balance: u64, blinding: &Scalar, amount: u64, rng: &mut OsRng)
    -> (Transfer, TransferSecrets) {
    rail.ledger.build_transfer(balance, blinding, amount, b"pvp",
                               None, &Scalar::ZERO, false, rng).unwrap()
}

struct Fixture { yen: Rail, usd: Rail, alice_key: Scalar, bob_key: Scalar }

fn fixture(rng: &mut OsRng) -> Fixture {
    Fixture {
        yen: rail(b"qomm:defmi:jpy", YEN, 0, rng),
        usd: rail(b"qomm:defmi:usd", 0, USD, rng),
        alice_key: Scalar::random(rng),
        bob_key: Scalar::random(rng),
    }
}

/// Alice pays yen, Bob pays dollars. Bob draws the secret and moves first, so
/// his deadline comes first and hers is later --- she is the one who needs room.
fn prepare_both(f: &mut Fixture, rng: &mut OsRng, deadline_a: u64, deadline_b: u64)
    -> (Swap, Swap, qomm_defmi::pvp::Leg, qomm_defmi::pvp::Leg) {
    let (bob_swap, _adaptor) = Swap::proposer(rng);
    let alice_swap = Swap::responder(bob_swap.adaptor_point);

    let (yen_leg, _) = transfer(&f.yen, YEN, &f.yen.alice_blinding, YEN, rng);
    let leg_a = alice_swap.prepare(&mut f.yen.ledger, b"leg-A", b"alice", b"bob",
                                   &f.alice_key, &yen_leg, b"pvp", false,
                                   deadline_a, rng).unwrap();

    let (usd_leg, _) = transfer(&f.usd, USD, &f.usd.bob_blinding, USD, rng);
    let leg_b = bob_swap.prepare(&mut f.usd.ledger, b"leg-B", b"bob", b"alice",
                                 &f.bob_key, &usd_leg, b"pvp", false,
                                 deadline_b, rng).unwrap();
    (alice_swap, bob_swap, leg_a, leg_b)
}

#[test]
fn both_legs_settle_and_neither_ledger_learns_of_the_other() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng);
    let (mut alice, bob, leg_a, leg_b) = prepare_both(&mut f, &mut rng, 100, 160);

    // Each party checks it can be released before leaving money behind it.
    assert!(leg_a.releasable_with(&alice.adaptor_point));
    assert!(leg_b.releasable_with(&bob.adaptor_point));
    assert!(f.yen.ledger.conserved() && f.usd.ledger.conserved());

    // Bob takes the yen. That publishes the signature Alice reads.
    let published = bob.claim(&mut f.yen.ledger, &leg_a, 90).unwrap();
    let secret = alice.learn(&leg_a, &published);
    assert_eq!(adaptor::public_key(&secret), alice.adaptor_point);

    // Alice takes the dollars with what she just learned.
    alice.claim_with(&mut f.usd.ledger, &leg_b, &secret, 120).unwrap();

    assert!(f.yen.ledger.pending_legs().is_empty());
    assert!(f.usd.ledger.pending_legs().is_empty());
    assert!(f.yen.ledger.conserved() && f.usd.ledger.conserved());
}

#[test]
fn a_counterparty_that_stops_after_preparing_costs_nobody_anything() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng);
    let (alice, bob, leg_a, leg_b) = prepare_both(&mut f, &mut rng, 100, 160);

    // Nothing is claimed. Both escrows expire and both are taken back.
    assert_eq!(alice.unwind(&mut f.yen.ledger, &leg_a, 90),
               Err("the escrow has not expired"));
    alice.unwind(&mut f.yen.ledger, &leg_a, 101).unwrap();
    bob.unwind(&mut f.usd.ledger, &leg_b, 161).unwrap();

    assert!(f.yen.ledger.conserved() && f.usd.ledger.conserved());
    assert!(f.yen.ledger.pending_legs().is_empty());
}

#[test]
fn the_second_mover_is_safe_exactly_while_the_window_is_open() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng);
    let (mut alice, bob, leg_a, leg_b) = prepare_both(&mut f, &mut rng, 100, 160);
    assert_eq!(Swap::window(&leg_a, &leg_b), Some(60));

    // Bob waits until the last moment his own leg allows.
    let published = bob.claim(&mut f.yen.ledger, &leg_a, 100).unwrap();
    let secret = alice.learn(&leg_a, &published);

    // Inside the window she is paid; past it she is not, and the money she was
    // owed goes back to Bob. That is the loss the window exists to bound.
    assert!(alice.claim_with(&mut f.usd.ledger, &leg_b, &secret, 161).is_err());
    alice.claim_with(&mut f.usd.ledger, &leg_b, &secret, 160).unwrap();
}

#[test]
fn nobody_can_release_a_leg_without_the_secret() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng);
    let (alice, _bob, leg_a, _leg_b) = prepare_both(&mut f, &mut rng, 100, 160);

    // Alice prepared this leg and holds its pre-signature, and still cannot
    // release it: holding the authority is not holding the secret.
    assert_eq!(alice.claim(&mut f.yen.ledger, &leg_a, 90).err(),
               Some("this side does not hold the secret yet"));
    assert_eq!(alice.claim_with(&mut f.yen.ledger, &leg_a,
                                &Scalar::random(&mut rng), 90).err(),
               Some("the release is not signed for this leg"));
    assert!(f.yen.ledger.pending(b"leg-A").is_some());
}

#[test]
fn an_escrow_cannot_be_claimed_twice_or_claimed_and_then_unwound() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng);
    let (alice, bob, leg_a, _leg_b) = prepare_both(&mut f, &mut rng, 100, 160);
    bob.claim(&mut f.yen.ledger, &leg_a, 90).unwrap();
    assert_eq!(bob.claim(&mut f.yen.ledger, &leg_a, 91).err(),
               Some("no such prepared leg"));
    assert_eq!(alice.unwind(&mut f.yen.ledger, &leg_a, 200), Err("no such prepared leg"));
    assert!(f.yen.ledger.conserved());
}

#[test]
fn a_leg_name_cannot_be_reused() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng);
    let (alice, _bob, _leg_a, _leg_b) = prepare_both(&mut f, &mut rng, 100, 160);
    let (again, _) = transfer(&f.yen, 0, &Scalar::ZERO, 0, &mut rng);
    assert_eq!(alice.prepare(&mut f.yen.ledger, b"leg-A", b"alice", b"bob",
                             &f.alice_key, &again, b"pvp", false, 100, &mut rng)
                    .err(),
               Some("that leg is already prepared"));
}

#[test]
fn the_two_published_signatures_have_nothing_in_common_to_join_on() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng);
    let (mut alice, bob, leg_a, leg_b) = prepare_both(&mut f, &mut rng, 100, 160);
    let on_yen = bob.claim(&mut f.yen.ledger, &leg_a, 90).unwrap();
    let secret = alice.learn(&leg_a, &on_yen);
    let on_usd = alice.claim_with(&mut f.usd.ledger, &leg_b, &secret, 120).unwrap();

    // What an observer of both ledgers holds. Neither component matches, and
    // neither difference is the adaptor: there is no value to join the two
    // records on, which is the property a hash lock would have given away.
    assert_ne!(on_yen.r, on_usd.r);
    assert_ne!(on_yen.s, on_usd.s);
    assert_ne!(on_yen.r - on_usd.r, alice.adaptor_point);
    assert_ne!(on_yen.s - on_usd.s, secret);
}

#[test]
fn money_held_in_escrow_is_still_on_the_books() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng);
    assert!(f.yen.ledger.conserved());
    let (_alice, _bob, _leg_a, _leg_b) = prepare_both(&mut f, &mut rng, 100, 160);
    // Alice's account is empty and the ledger still adds up.
    assert!(f.yen.ledger.conserved());
    assert_eq!(f.yen.ledger.pending_legs(), vec![b"leg-A".to_vec()]);
}
