//! Handing an auditor one slice of a wallet.
//!
//! The scoping is in the address rather than in the key, so what these tests
//! are about is what a scope's key reaches --- and, at least as much, what it
//! does not, because three of the limits are permanent.

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use qomm_defmi::notes::NoteLedger;
use qomm_defmi::reconcile::{check, prove, Attestation};
use qomm_defmi::viewing::*;
use qomm_zk::pedersen::{asset_tag, Pedersen};
use rand::rngs::OsRng;
use rand::Rng;

const NOW: u64 = 1_780_000_000;
/// Bulletproofs wants a power of two, and 40 is not one --- a ledger built at
/// 40 bits proves nothing and fails at the first spend rather than at
/// construction, which is worth knowing before choosing a rail width.
const BITS: usize = 32;

fn asset_key() -> Pedersen {
    Pedersen::new(b"qomm:defmi:note:v1").with_value_generator(asset_tag(3))
}

fn fill(ledger: &mut NoteLedger, owner: &ScopedWallet, scopes: &[&str], per: usize)
    -> Vec<u64>
{
    let mut rng = OsRng;
    let key = asset_key();
    let mut planted = vec![0u64; scopes.len()];
    for (i, scope) in scopes.iter().enumerate() {
        for _ in 0..per {
            let value = rng.gen_range(1..500);
            let blinding = Scalar::random(&mut rng);
            let note = ledger.build_note(&owner.address(scope), value,
                                         key.commit_u64(value, &blinding),
                                         &blinding, &mut rng);
            ledger.add(note);
            planted[i] += value;
        }
    }
    planted
}

#[test]
fn a_scope_sees_its_own_notes_and_no_others() {
    let mut rng = OsRng;
    let mut ledger = NoteLedger::new(Pedersen::new(b"qomm:defmi:note:v1"), BITS);
    let owner = ScopedWallet::new(&mut rng);
    let scopes = ["2026Q2:JPY", "2026Q3:JPY", "2026Q3:USD"];
    let planted = fill(&mut ledger, &owner, &scopes, 5);
    let stranger = ScopedWallet::new(&mut rng);
    fill(&mut ledger, &stranger, &["theirs"], 4);

    let grant = owner.grant("2026Q3:JPY", "an auditor", NOW, 90);
    let seen = scan_scope(&ledger, &grant, &asset_key());
    assert_eq!(seen.len(), 5);
    assert_eq!(total_seen(&seen), planted[1]);
}

#[test]
fn a_scope_key_says_nothing_about_a_sibling_or_the_seed() {
    let first = derive(b"a-seed", b"view", "2026Q3:JPY");
    let second = derive(b"a-seed", b"view", "2026Q4:JPY");
    let spend = derive(b"a-seed", b"spend", "2026Q3:JPY");
    assert_ne!(first, second);
    assert_ne!(first, spend);
    assert_ne!(derive(b"another-seed", b"view", "2026Q3:JPY"), first);
}

#[test]
fn a_view_key_recovers_no_serial_so_it_cannot_spend() {
    // Not withheld by policy: the tuple that comes back has nowhere to put one,
    // and the scalar a serial needs is not in a ViewKey at all.
    let mut rng = OsRng;
    let mut ledger = NoteLedger::new(Pedersen::new(b"qomm:defmi:note:v1"), BITS);
    let owner = ScopedWallet::new(&mut rng);
    fill(&mut ledger, &owner, &["s"], 3);
    let grant = owner.grant("s", "an auditor", NOW, 90);
    let seen = scan_scope(&ledger, &grant, &asset_key());
    assert_eq!(seen.len(), 3);
    // the owner's own scan does get serials --- that is the difference
    let spender = owner.wallet("s");
    for (_, opening) in ledger.scan(&spender, &asset_key()) {
        assert_ne!(opening.serial, Scalar::ZERO);
    }
}

#[test]
fn the_wallet_can_still_spend_what_it_let_an_auditor_read() {
    let mut rng = OsRng;
    let mut ledger = NoteLedger::new(Pedersen::new(b"qomm:defmi:note:v1"), BITS);
    let owner = ScopedWallet::new(&mut rng);
    fill(&mut ledger, &owner, &["s"], 4);
    let _grant = owner.grant("s", "an auditor", NOW, 90);
    let spender = owner.wallet("s");
    let found = ledger.scan(&spender, &asset_key());
    assert_eq!(found.len(), 4, "a grant is a copy of a reading ability, not a transfer");
}

#[test]
fn a_grant_is_signed_current_and_about_the_address_it_names() {
    let mut rng = OsRng;
    let owner = ScopedWallet::new(&mut rng);
    let grant = owner.grant("s", "an auditor", NOW, 90);
    assert_eq!(check_grant(&grant, &owner.public_identity(), NOW + 10), Ok(()));
    assert!(check_grant(&grant, &owner.public_identity(), NOW - 10).is_err());
    assert!(check_grant(&grant, &owner.public_identity(), NOW + 91 * 86_400)
        .unwrap_err().contains("expired"));
    let other = ScopedWallet::new(&mut rng);
    assert!(check_grant(&grant, &other.public_identity(), NOW + 10).is_err());
}

#[test]
fn an_unsigned_grant_is_a_key_somebody_wrote_down() {
    let mut rng = OsRng;
    let owner = ScopedWallet::new(&mut rng);
    let mut grant = owner.grant("s", "an auditor", NOW, 90);
    grant.signature = None;
    assert!(check_grant(&grant, &owner.public_identity(), NOW + 10)
        .unwrap_err().contains("wrote down"));
}

#[test]
fn revocation_is_the_next_scope_and_not_a_message() {
    // The limit most likely to be assumed away: what stops an auditor seeing
    // next quarter is that next quarter has its own address, not a withdrawal.
    let mut rng = OsRng;
    let mut ledger = NoteLedger::new(Pedersen::new(b"qomm:defmi:note:v1"), BITS);
    let owner = ScopedWallet::new(&mut rng);
    fill(&mut ledger, &owner, &["s"], 2);
    let grant = owner.grant("s", "an auditor", NOW, 1);
    assert!(check_grant(&grant, &owner.public_identity(), NOW + 2 * 86_400).is_err());

    let key = asset_key();
    let b1 = Scalar::random(&mut rng);
    let note = ledger.build_note(&owner.address("s"), 4242,
                                 key.commit_u64(4242, &b1), &b1, &mut rng);
    ledger.add(note);
    let seen = scan_scope(&ledger, &grant, &key);
    assert!(seen.iter().any(|(_, v, _)| *v == 4242),
            "an expired grant still reads its address");

    let b2 = Scalar::random(&mut rng);
    let later = ledger.build_note(&owner.address("s+1"), 777,
                                  key.commit_u64(777, &b2), &b2, &mut rng);
    ledger.add(later);
    let seen = scan_scope(&ledger, &grant, &key);
    assert!(!seen.iter().any(|(_, v, _)| *v == 777),
            "and reads nothing sent to the next one");
}

#[test]
fn a_scope_reconciles_against_a_figure_without_opening_a_note() {
    // The join between the two modules: a scope is a set of positions, and
    // reconciliation turns a set of positions into agreement with a number.
    let mut rng = OsRng;
    let mut ledger = NoteLedger::new(Pedersen::new(b"qomm:defmi:note:v1"), BITS);
    let owner = ScopedWallet::new(&mut rng);
    fill(&mut ledger, &owner, &["2026Q3"], 8);
    let grant = owner.grant("2026Q3", "an auditor", NOW, 90);
    let key = asset_key();
    let (commitments, blindings, total) = scope_commitments(&ledger, &grant, &key);
    assert_eq!(commitments.len(), 8);

    let attestation = Attestation {
        register: "the auditor's own record".into(), account: "2026Q3".into(),
        asset: "an instrument".into(), total, as_of: "2026-09-30".into(),
        signature: None,
    };
    let r = prove(&key, &commitments, &blindings, &attestation, &mut rng).unwrap();
    assert_eq!(check(&key, &commitments, &r, None), Ok(()));

    let mut wrong = attestation.clone();
    wrong.total = total + 1;
    let r = prove(&key, &commitments, &blindings, &wrong, &mut rng).unwrap();
    assert!(check(&key, &commitments, &r, None).is_err());
}

// --- outflows, and the boundary that makes them a different disclosure ----

fn spend_one(ledger: &mut NoteLedger, owner: &ScopedWallet, scope: &str,
             registry: &qomm_defmi::assets::AssetRegistry, rng: &mut OsRng)
    -> Scalar
{
    use qomm_defmi::notes::{ring_for, Wallet};
    let key = asset_key();
    let wallet = owner.wallet(scope);
    let (index, opening) = ledger.scan(&wallet, &key).into_iter().next()
        .expect("something to spend");
    let serial = opening.serial;
    let (tag, gamma) = registry.blind(3, false, rng).expect("tag");
    let ring = ring_for(ledger.notes.len(), index, 2, 7).expect("ring");
    let payee = Wallet::new(rng);
    let spend = ledger.build_spend(
        &ring, index, &opening, &tag.point, &gamma,
        // two outputs, because the ledger's range gens are sized for a payee
        // and a change note and that is the shape a spend has
        &[(payee.address, opening.value), (owner.address(scope), 0)],
        b"ctx", rng).expect("spend");
    ledger.check_spend(&ring, &spend.proof, b"ctx", rng).expect("it verifies");
    ledger.apply_spend(&spend.proof, spend.notes).expect("applied");
    serial
}

#[test]
fn a_wallet_can_say_what_it_spent_and_sign_it() {
    let mut rng = OsRng;
    let mut ledger = NoteLedger::new(Pedersen::new(b"qomm:defmi:note:v1"), BITS);
    let owner = ScopedWallet::new(&mut rng);
    fill(&mut ledger, &owner, &["s"], 4);
    let registry = qomm_defmi::assets::AssetRegistry::new(
        Pedersen::new(b"qomm:defmi:note:v1"), 16);
    let spent = spend_one(&mut ledger, &owner, "s", &registry, &mut rng);

    let disclosure = owner.disclose_spends(&ledger, "s", "an auditor",
                                           &asset_key(), NOW);
    assert!(disclosure.serials.contains(&spent));
    assert_eq!(check_spend_disclosure(&disclosure, &owner.public_identity(), &ledger),
               Ok(disclosure.serials.len()));
}

#[test]
fn an_unsigned_or_misattributed_disclosure_is_refused() {
    let mut rng = OsRng;
    let mut ledger = NoteLedger::new(Pedersen::new(b"qomm:defmi:note:v1"), BITS);
    let owner = ScopedWallet::new(&mut rng);
    fill(&mut ledger, &owner, &["s"], 2);
    let mut disclosure = owner.disclose_spends(&ledger, "s", "an auditor",
                                               &asset_key(), NOW);
    let other = ScopedWallet::new(&mut rng);
    assert!(check_spend_disclosure(&disclosure, &other.public_identity(), &ledger)
        .is_err());
    disclosure.signature = None;
    assert!(check_spend_disclosure(&disclosure, &owner.public_identity(), &ledger)
        .is_err());
}

#[test]
fn a_disclosure_naming_a_spend_the_ledger_never_saw_is_refused() {
    let mut rng = OsRng;
    let mut ledger = NoteLedger::new(Pedersen::new(b"qomm:defmi:note:v1"), BITS);
    let owner = ScopedWallet::new(&mut rng);
    fill(&mut ledger, &owner, &["s"], 2);
    let mut disclosure = owner.disclose_spends(&ledger, "s", "an auditor",
                                               &asset_key(), NOW);
    disclosure.serials.push(Scalar::random(&mut rng));
    disclosure.signature = Some(owner.sign_disclosure(&disclosure));
    assert!(check_spend_disclosure(&disclosure, &owner.public_identity(), &ledger)
        .is_err());
}

#[test]
fn giving_one_party_both_disclosures_gives_it_the_wallet() {
    // Not a warning in a comment: spending needs the serial and the note's
    // blinding, and a view key recovers the blinding. So the two disclosures
    // are for different parties, and this is the check that says when they
    // are not.
    let mut rng = OsRng;
    let mut ledger = NoteLedger::new(Pedersen::new(b"qomm:defmi:note:v1"), BITS);
    let owner = ScopedWallet::new(&mut rng);
    fill(&mut ledger, &owner, &["s"], 2);
    let grant = owner.grant("s", "an auditor", NOW, 90);
    let outflows = owner.disclose_spends(&ledger, "s", "an auditor",
                                         &asset_key(), NOW);
    assert!(conflicts_with(&grant, &outflows));

    let elsewhere = owner.disclose_spends(&ledger, "t", "an auditor",
                                          &asset_key(), NOW);
    assert!(!conflicts_with(&grant, &elsewhere));
}

#[test]
fn what_a_disclosure_cannot_do_is_be_complete() {
    // A wallet can leave a spend out and nothing here catches it, which is the
    // same shape as a clearing house omitting a trade. Written down where the
    // mechanism is rather than left to be discovered.
    let mut rng = OsRng;
    let mut ledger = NoteLedger::new(Pedersen::new(b"qomm:defmi:note:v1"), BITS);
    let owner = ScopedWallet::new(&mut rng);
    fill(&mut ledger, &owner, &["s"], 4);
    let registry = qomm_defmi::assets::AssetRegistry::new(
        Pedersen::new(b"qomm:defmi:note:v1"), 16);
    spend_one(&mut ledger, &owner, "s", &registry, &mut rng);

    let mut disclosure = owner.disclose_spends(&ledger, "s", "an auditor",
                                               &asset_key(), NOW);
    disclosure.serials.clear();
    disclosure.signature = Some(owner.sign_disclosure(&disclosure));
    assert_eq!(check_spend_disclosure(&disclosure, &owner.public_identity(), &ledger),
               Ok(0), "an empty list checks out, and that is the limit");
}
