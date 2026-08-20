//! Intraday credit and the waterfall that catches what it does not cover.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_defmi::credit::*;
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;

fn key() -> Pedersen { Pedersen::new(b"qomm:defmi:v1") }

#[test]
fn a_cap_covered_by_collateral_is_underwritten() {
    let mut rng = OsRng;
    let ctx = CreditCtx::new(key(), 64);
    let line = ctx.grant(b"p0", "securities", 8_000_000, &Scalar::random(&mut rng),
                         10_000_000, &Scalar::random(&mut rng), 500).unwrap();
    assert_eq!(ctx.check(&line), Ok(()));
}

#[test]
fn a_cap_the_collateral_does_not_support_is_refused() {
    let mut rng = OsRng;
    let ctx = CreditCtx::new(key(), 64);
    assert_eq!(
        ctx.grant(b"p0", "cash", 10_000_000, &Scalar::random(&mut rng),
                  10_000_000, &Scalar::random(&mut rng), 500).err(),
        Some("the pledged collateral does not cover the cap"));
}

#[test]
fn a_backing_proof_from_another_line_does_not_transfer() {
    let mut rng = OsRng;
    let ctx = CreditCtx::new(key(), 64);
    let mut line = ctx.grant(b"p0", "cash", 8_000_000, &Scalar::random(&mut rng),
                             10_000_000, &Scalar::random(&mut rng), 500).unwrap();
    let other = ctx.grant(b"p1", "cash", 1_000, &Scalar::random(&mut rng),
                          10_000_000, &Scalar::random(&mut rng), 500).unwrap();
    line.backing = other.backing;
    line.backing_commitment = other.backing_commitment;
    assert!(ctx.check(&line).is_err());
}

fn waterfall(rng: &mut OsRng, balances: &[u64]) -> (Waterfall, Vec<Scalar>) {
    let k = key();
    let blindings: Vec<Scalar> = balances.iter().map(|_| Scalar::random(rng)).collect();
    let names = ["defaulter collateral", "defaulter fund share", "FMI capital",
                 "surviving members"];
    let tranches = balances.iter().zip(blindings.iter()).enumerate()
        .map(|(i, (b, r))| Tranche {
            name: names.get(i).unwrap_or(&"further").to_string(),
            commitment: k.commit_u64(*b, r),
        })
        .collect();
    (Waterfall::new(k, tranches, 32), blindings)
}

#[test]
fn the_waterfall_consumes_tranches_in_order() {
    let mut rng = OsRng;
    let balances = [300u64, 200, 500, 5_000];
    let (wf, blindings) = waterfall(&mut rng, &balances);
    for (shortfall, expected) in [
        (250u64, vec![250u64, 0, 0, 0]),
        (700, vec![300, 200, 200, 0]),
        (1_200, vec![300, 200, 500, 200]),
    ] {
        let (resolution, amounts) = wf
            .build(shortfall, &Scalar::random(&mut rng), &balances, &blindings, &mut rng)
            .unwrap();
        assert_eq!(amounts, expected);
        assert_eq!(wf.check(&resolution, &mut rng), Ok(()));
    }
}

#[test]
fn a_shortfall_larger_than_the_waterfall_is_refused() {
    let mut rng = OsRng;
    let balances = [300u64, 200, 500, 5_000];
    let (wf, blindings) = waterfall(&mut rng, &balances);
    assert_eq!(
        wf.build(99_999, &Scalar::random(&mut rng), &balances, &blindings, &mut rng)
            .err(),
        Some("the shortfall exceeds what the waterfall holds"));
}

#[test]
fn skipping_a_tranche_is_caught_by_the_ordering_proof() {
    // the real attack: draw from below while the layer above still has money
    use qomm_zk::sigma::prove_product;
    let mut rng = OsRng;
    let balances = [300u64, 200, 500, 5_000];
    let (wf, blindings) = waterfall(&mut rng, &balances);
    let k = key();
    let shortfall = 200u64;
    let shortfall_blinding = Scalar::random(&mut rng);

    let mut draws = Vec::new();
    for (index, (balance, blinding)) in balances.iter().zip(blindings.iter()).enumerate() {
        let amount = if index == 1 { shortfall } else { 0 };
        let amount_blinding = if index == 1 { shortfall_blinding } else { Scalar::ZERO };
        let left = balance - amount;
        let left_blinding = blinding - amount_blinding;
        let mut t = merlin::Transcript::new(b"qomm:waterfall:within");
        t.append_u64(b"k", index as u64);
        let (within, commitments) = bulletproofs::RangeProof::prove_multiple(
            &bulletproofs::BulletproofGens::new(32, 1),
            &bulletproofs::PedersenGens { B: k.g, B_blinding: k.h },
            &mut t, &[left], &[left_blinding], 32).unwrap();
        let ordering = if index == 0 { None } else {
            let above_value = balances[index - 1] - if index - 1 == 1 { shortfall } else { 0 };
            let above_blinding = blindings[index - 1];
            let mut t = merlin::Transcript::new(b"qomm:waterfall:order");
            t.append_u64(b"k", index as u64);
            Some(prove_product(&k, &mut t, &k.commit_u64(above_value, &above_blinding),
                               &Scalar::from(above_value), &above_blinding,
                               &Scalar::from(amount), &amount_blinding, &Scalar::ZERO,
                               &mut rng))
        };
        draws.push(Draw {
            tranche: index,
            amount_commitment: k.commit_u64(amount, &amount_blinding),
            within, within_commitment: commitments[0], ordering,
        });
    }
    let residual = k.commit_u64(shortfall, &shortfall_blinding)
        - draws.iter().map(|d| d.amount_commitment).sum::<RistrettoPoint>();
    let mut t = merlin::Transcript::new(b"qomm:waterfall:balance");
    let balance = qomm_zk::sigma::prove_opening(&k, &mut t, &residual, &Scalar::ZERO,
                                                &Scalar::ZERO, &mut rng);
    let mut st = merlin::Transcript::new(b"qomm:waterfall:shortfall");
    let (shortfall_range, sc) = bulletproofs::RangeProof::prove_multiple(
        &bulletproofs::BulletproofGens::new(32, 1),
        &bulletproofs::PedersenGens { B: k.g, B_blinding: k.h },
        &mut st, &[shortfall], &[shortfall_blinding], 32).unwrap();
    let forged = Resolution {
        shortfall_commitment: k.commit_u64(shortfall, &shortfall_blinding),
        shortfall_range, shortfall_range_commitment: sc[0], draws, balance,
    };
    assert!(wf.check(&forged, &mut rng).is_err());
}

#[test]
fn the_tranches_after_a_resolution_are_still_commitments() {
    let mut rng = OsRng;
    let balances = [300u64, 200, 500, 5_000];
    let (wf, blindings) = waterfall(&mut rng, &balances);
    let (resolution, amounts) = wf
        .build(700, &Scalar::random(&mut rng), &balances, &blindings, &mut rng).unwrap();
    let after = wf.applied(&resolution);
    for ((tranche, before), draw) in after.iter().zip(wf.tranches.iter()).zip(resolution.draws.iter()) {
        assert_eq!(tranche.commitment, before.commitment - draw.amount_commitment);
    }
    assert_eq!(amounts.iter().sum::<u64>(), 700);
}
