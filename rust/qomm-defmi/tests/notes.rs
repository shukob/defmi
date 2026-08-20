//! Notes: holdings that do not sit at an address.

use curve25519_dalek::scalar::Scalar;
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::notes::*;
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;

const BITS: usize = 32;
const RING: usize = 8;

struct Pool { key: Pedersen, registry: AssetRegistry, ledger: NoteLedger,
              alice: Wallet, bob: Wallet, asset_key: Pedersen }

fn pool(rng: &mut OsRng) -> Pool {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let asset_key = key.with_value_generator(registry.tags[3]);
    let mut ledger = NoteLedger::new(key.clone(), BITS);
    let alice = Wallet::new(rng);
    let bob = Wallet::new(rng);
    for i in 0..RING {
        let owner = if i == 0 { alice.address } else { Wallet::new(rng).address };
        let value = 1_000 + i as u64;
        let blinding = Scalar::random(rng);
        let note = ledger.build_note(&owner, value,
                                     asset_key.commit_u64(value, &blinding), &blinding, rng);
        ledger.add(note);
    }
    Pool { key, registry, ledger, alice, bob, asset_key }
}

fn spend(p: &Pool, rng: &mut OsRng, tag_asset: u32, seed: u64)
    -> Result<(Vec<usize>, SpendProof, Vec<Note>), &'static str> {
    let found = p.ledger.scan(&p.alice, &p.asset_key);
    let (index, opening) = found[0];
    let (tag, gamma) = p.registry.blind(tag_asset, false, rng)?;
    let ring = ring_for(p.ledger.notes.len(), index, RING, seed)?;
    let spend = p.ledger.build_spend(
        &ring, index, &opening, &tag.point, &gamma,
        &[(p.bob.address, 400), (p.alice.address, opening.value - 400)], b"ctx", rng)?;
    Ok((ring, spend.proof, spend.notes))
}

#[test]
fn a_spend_verifies_and_the_payee_finds_its_note() {
    let mut rng = OsRng;
    let mut p = pool(&mut rng);
    let (ring, proof, notes) = spend(&p, &mut rng, 3, 7).unwrap();
    assert_eq!(p.ledger.check_spend(&ring, &proof, b"ctx", &mut rng), Ok(()));
    p.ledger.apply_spend(&proof, notes).unwrap();
    let received = p.ledger.scan(&p.bob, &p.asset_key);
    assert_eq!(received.iter().map(|(_, o)| o.value).collect::<Vec<_>>(), vec![400]);
}

#[test]
fn two_payments_to_one_address_are_unlinkable() {
    let mut rng = OsRng;
    let mut p = pool(&mut rng);
    let mut made = Vec::new();
    for _ in 0..2 {
        let blinding = Scalar::random(&mut rng);
        let note = p.ledger.build_note(&p.bob.address, 100,
                                       p.asset_key.commit_u64(100, &blinding), &blinding, &mut rng);
        made.push(note.clone());
        p.ledger.add(note);
    }
    assert_ne!(p.ledger.commitment_of(&made[0]), p.ledger.commitment_of(&made[1]));
    assert_ne!(made[0].ephemeral, made[1].ephemeral);
    assert_eq!(p.ledger.scan(&p.bob, &p.asset_key).len(), 2);
}

#[test]
fn scanning_finds_only_your_own() {
    let mut rng = OsRng;
    let p = pool(&mut rng);
    assert_eq!(p.ledger.scan(&p.alice, &p.asset_key).len(), 1);
    assert!(p.ledger.scan(&p.bob, &p.asset_key).is_empty());
    assert!(p.ledger.scan(&Wallet::new(&mut rng), &p.asset_key).is_empty());
}

#[test]
fn a_note_spends_once() {
    let mut rng = OsRng;
    let mut p = pool(&mut rng);
    let (ring, proof, notes) = spend(&p, &mut rng, 3, 9).unwrap();
    p.ledger.apply_spend(&proof, notes).unwrap();
    assert_eq!(p.ledger.check_spend(&ring, &proof, b"ctx", &mut rng),
               Err("serial already spent"));
}

#[test]
fn a_reblinded_serial_cannot_stand_in_for_a_fresh_one() {
    let mut rng = OsRng;
    let mut p = pool(&mut rng);
    let (ring, proof, notes) = spend(&p, &mut rng, 3, 11).unwrap();
    let shifted = proof.serial_point + p.key.h * Scalar::from(12_345u64);
    p.ledger.apply_spend(&proof, notes).unwrap();
    let replay = SpendProof { serial_point: shifted, ..proof };
    assert_eq!(p.ledger.check_spend(&ring, &replay, b"ctx", &mut rng),
               Err("the serial is not a bare power of the base point"));
}

#[test]
fn a_tag_for_the_wrong_asset_cannot_spend() {
    let mut rng = OsRng;
    let p = pool(&mut rng);
    let (ring, proof, _) = spend(&p, &mut rng, 7, 13).unwrap();
    assert_eq!(p.ledger.check_spend(&ring, &proof, b"ctx", &mut rng),
               Err("no note in the ring carries this serial"));
}

#[test]
fn outputs_must_sum_to_the_note() {
    let mut rng = OsRng;
    let p = pool(&mut rng);
    let found = p.ledger.scan(&p.alice, &p.asset_key);
    let (index, opening) = found[0];
    let (tag, gamma) = p.registry.blind(3, false, &mut rng).unwrap();
    let ring = ring_for(p.ledger.notes.len(), index, RING, 3).unwrap();
    assert_eq!(
        p.ledger.build_spend(&ring, index, &opening, &tag.point, &gamma,
                             &[(p.bob.address, 400), (p.alice.address, 9_999)], b"ctx", &mut rng)
            .err(),
        Some("outputs do not sum to the note being spent"));
}

#[test]
fn the_spend_looks_the_same_wherever_the_real_note_sits() {
    let mut rng = OsRng;
    let p = pool(&mut rng);
    let mut shapes = std::collections::HashSet::new();
    for seed in 0..6u64 {
        let (ring, proof, _) = spend(&p, &mut rng, 3, seed).unwrap();
        assert_eq!(p.ledger.check_spend(&ring, &proof, b"ctx", &mut rng), Ok(()));
        shapes.insert((proof.ring.size_bytes(), proof.output_range.to_bytes().len(),
                       proof.outputs.len()));
    }
    assert_eq!(shapes.len(), 1, "the hidden position leaks");
}

#[test]
fn the_pool_keeps_spent_notes() {
    let mut rng = OsRng;
    let mut p = pool(&mut rng);
    let before = p.ledger.notes.len();
    let (_, proof, notes) = spend(&p, &mut rng, 3, 17).unwrap();
    p.ledger.apply_spend(&proof, notes).unwrap();
    assert_eq!(p.ledger.notes.len(), before + 2);
}

#[test]
fn a_ring_has_to_be_a_power_of_two_and_fit_the_pool() {
    assert!(ring_for(8, 0, 6, 1).is_err());
    assert!(ring_for(4, 0, 8, 1).is_err());
    assert!(ring_for(8, 0, 8, 1).is_ok());
}
