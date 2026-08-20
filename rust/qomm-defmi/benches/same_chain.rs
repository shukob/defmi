//! Two DeFMI deployments on one chain: one transaction, or two and an adaptor.
//!
//! Across two chains there is no choice --- nothing can span them, so the
//! adaptor and its deadline window are the only way. On one chain there is a
//! choice, and it is not the obvious one.
//!
//! A single transaction calling both venues gets atomicity from the chain for
//! nothing: both apply or the transaction reverts, and the exposure window is
//! zero. But that transaction *is* the link. Two transactions with an adaptor
//! keep the two legs cryptographically unrelated and pay a window of at least
//! one block. Both cannot be had, because being one transaction is what makes
//! it atomic and what makes it linkable.
//!
//! So three things are worth a number, and the third is the one that decides:
//!
//!   1. what each arm costs the chain in state --- exact, not timed
//!   2. what each arm costs in verification --- timed
//!   3. **what an observer reading the chain can still join**
//!
//! The prediction for the third, written before running it: the adaptor makes
//! the two *claims* unrelated, and does nothing about the two *prepares*, which
//! name account handles. An observer who joins "Alice pays on venue A" to
//! "Alice is paid on venue B" needs no cryptanalysis at all. If that is right,
//! the adaptor buys nothing on account rails and the whole choice above is a
//! false one until the rails are note rails.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_defmi::chain::{Call, ChainState, Delta, Observable};
use qomm_defmi::ledger::{Ledger, Transfer};
use qomm_defmi::pvp::Swap;
use qomm_measure::{hosts, Summary};
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::time::Instant;

const BITS: usize = 32;
const AMOUNT: u64 = 1_000;
const BALANCE: u64 = 1_000_000;

fn shell(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd).args(args).output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// One venue: a DeFMI deployment, its off-chain ledger and the chain state it
/// keeps. Two of these are two contract addresses on one chain.
struct Venue {
    name: String,
    ledger: Ledger,
    chain: ChainState,
    /// What each handle holds and the blinding that opens it. Tracked because
    /// a party that swaps twice pays from a moved balance the second time, and
    /// building the second transfer against the first one's opening is how a
    /// benchmark quietly stops measuring anything.
    holdings: BTreeMap<Vec<u8>, (u64, Scalar)>,
}

impl Venue {
    /// Every party is banked on every venue. A cross-currency swap needs that:
    /// whoever pays yen here is paid dollars there, so both need a handle on
    /// both. Modelling one venue per party would make the observer's job look
    /// harder than it is.
    fn new(name: &str, handles: &[Vec<u8>], rng: &mut OsRng) -> Venue {
        let key = Pedersen::new(name.as_bytes());
        let mut ledger = Ledger::new(key.clone(), BITS);
        let mut chain = ChainState::new();
        let mut holdings = BTreeMap::new();
        for handle in handles {
            let b = Scalar::random(rng);
            let commitment = key.commit_u64(BALANCE, &b);
            ledger.open(handle, commitment);
            chain.open(handle, commitment);
            holdings.insert(handle.clone(), (BALANCE, b));
        }
        Venue { name: name.to_string(), ledger, chain, holdings }
    }

    /// Build a transfer and move this venue's own bookkeeping with it, so a
    /// second transfer from the same handle is built against the balance the
    /// first one left.
    fn transfer(&mut self, payer: &[u8], payee: &[u8], rng: &mut OsRng) -> Transfer {
        let (balance, blinding) = self.holdings[payer];
        let (transfer, secrets) = self.ledger
            .build_transfer(balance, &blinding, AMOUNT, b"same-chain",
                            None, &Scalar::ZERO, false, rng).unwrap();
        self.holdings.insert(payer.to_vec(),
                             (balance - AMOUNT, secrets.remainder_blinding));
        let (had, opening) = self.holdings[payee];
        self.holdings.insert(payee.to_vec(), (had + AMOUNT, opening + secrets.payee_delta));
        transfer
    }
}

/// One party pair doing one swap.
struct Pair { a: Vec<u8>, b: Vec<u8>, index: usize }

fn pairs(count: usize, distinct: bool) -> Vec<Pair> {
    (0..count).map(|i| {
        // `distinct` decides the only thing that matters to an observer: are
        // these k swaps between k different pairs of parties, or k swaps
        // between the same two? The first is what a venue with many users looks
        // like; the second is the best case the design could hope for.
        let who = if distinct { i } else { 0 };
        Pair { a: format!("party-a-{who}").into_bytes(),
               b: format!("party-b-{who}").into_bytes(), index: i }
    }).collect()
}

fn handles(count: usize, distinct: bool) -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    for p in pairs(count, distinct) {
        for h in [p.a, p.b] {
            if !all.contains(&h) { all.push(h); }
        }
    }
    all
}

struct ArmResult {
    calls: usize,
    delta: Delta,
    verify_ms: f64,
    log: Vec<Observable>,
}

fn merge(into: &mut Delta, d: Delta) { into.merge(&d); }

/// Both legs in one call to one transaction that touches both venues.
fn one_transaction(count: usize, distinct: bool, rng: &mut OsRng) -> ArmResult {
    let all = handles(count, distinct);
    let mut yen = Venue::new("jpy", &all, rng);
    let mut usd = Venue::new("usd", &all, rng);
    let mut delta = Delta::default();
    let mut log = Vec::new();
    let mut calls = 0;

    let start = Instant::now();
    for p in pairs(count, distinct) {
        let ta = yen.transfer(&p.a, &p.b, rng);
        let tb = usd.transfer(&p.b, &p.a, rng);
        yen.ledger.check_transfer(&p.a, &ta, b"same-chain", false).unwrap();
        usd.ledger.check_transfer(&p.b, &tb, b"same-chain", false).unwrap();
        yen.ledger.apply_transfer(&p.a, &p.b, &ta);
        usd.ledger.apply_transfer(&p.b, &p.a, &tb);

        let mut nullifier = [0u8; 32];
        nullifier[..8].copy_from_slice(&(p.index as u64).to_be_bytes());
        merge(&mut delta, yen.chain.settle(nullifier, 1_000, 1,
            &[(&p.a, ta.remainder_commitment), (&p.b, ta.amount_commitment)]).unwrap());
        merge(&mut delta, usd.chain.settle(nullifier, 1_000, 1,
            &[(&p.b, tb.remainder_commitment), (&p.a, tb.amount_commitment)]).unwrap());
        calls += 1;

        // One transaction, both venues. That is the record an observer reads.
        log.push(Observable {
            block: 0, venue: format!("{}+{}", yen.name, usd.name), call: Call::Settle,
            handles: vec![p.a.clone(), p.b.clone()], leg: None,
        });
    }
    ArmResult { calls, delta, verify_ms: start.elapsed().as_secs_f64() * 1e3, log }
}

/// Two transactions per leg, joined by an adaptor signature.
fn with_adaptor(count: usize, distinct: bool, rng: &mut OsRng) -> ArmResult {
    let all = handles(count, distinct);
    let mut yen = Venue::new("jpy", &all, rng);
    let mut usd = Venue::new("usd", &all, rng);
    let mut delta = Delta::default();
    let mut log = Vec::new();
    let mut calls = 0;

    let start = Instant::now();
    for p in pairs(count, distinct) {
        let (bob, _) = Swap::proposer(rng);
        let mut alice = Swap::responder(bob.adaptor_point);
        let (leg_a, leg_b) = (format!("A{}", p.index).into_bytes(),
                              format!("B{}", p.index).into_bytes());

        let ta = yen.transfer(&p.a, &p.b, rng);
        let tb = usd.transfer(&p.b, &p.a, rng);
        let la = alice.prepare(&mut yen.ledger, &leg_a, &p.a, &p.b,
                               &Scalar::random(rng), &ta, b"same-chain",
                               false, 100, rng).unwrap();
        let lb = bob.prepare(&mut usd.ledger, &leg_b, &p.b, &p.a,
                             &Scalar::random(rng), &tb, b"same-chain",
                             false, 160, rng).unwrap();
        merge(&mut delta, yen.chain.prepare(&leg_a, &p.a, &p.b,
            ta.remainder_commitment, ta.amount_commitment).unwrap());
        merge(&mut delta, usd.chain.prepare(&leg_b, &p.b, &p.a,
            tb.remainder_commitment, tb.amount_commitment).unwrap());

        // A prepare names both parties: it is a transfer, and a transfer says
        // who is paying whom. Nothing about the adaptor changes that.
        log.push(Observable { block: 0, venue: yen.name.clone(), call: Call::Prepare,
                              handles: vec![p.a.clone(), p.b.clone()],
                              leg: Some(leg_a.clone()) });
        log.push(Observable { block: 0, venue: usd.name.clone(), call: Call::Prepare,
                              handles: vec![p.b.clone(), p.a.clone()],
                              leg: Some(leg_b.clone()) });

        let published = bob.claim(&mut yen.ledger, &la, 90).unwrap();
        let secret = alice.learn(&la, &published);
        alice.claim_with(&mut usd.ledger, &lb, &secret, 120).unwrap();
        merge(&mut delta, yen.chain.claim(&leg_a, RistrettoPoint::default()).unwrap());
        merge(&mut delta, usd.chain.claim(&leg_b, RistrettoPoint::default()).unwrap());
        calls += 4;

        // A claim names only the escrow and a signature. This is the part the
        // adaptor makes unrelated across the two venues.
        log.push(Observable { block: 1, venue: yen.name.clone(), call: Call::Claim,
                              handles: vec![], leg: Some(leg_a) });
        log.push(Observable { block: 2, venue: usd.name.clone(), call: Call::Claim,
                              handles: vec![], leg: Some(leg_b) });
    }
    ArmResult { calls, delta, verify_ms: start.elapsed().as_secs_f64() * 1e3, log }
}

/// What a reader of the chain can still join, using only what the log exposes.
///
/// One stated strategy, run over the real records rather than reasoned about:
/// take every call on the first venue, find the calls on the second venue that
/// name the same two handles, and guess uniformly among them. A call that names
/// no handle offers this strategy nothing.
fn observer_success(log: &[Observable], count: usize) -> f64 {
    let mut total = 0.0;
    let mut scored = 0usize;
    for (i, entry) in log.iter().enumerate() {
        if entry.call == Call::Settle {
            // One call carries both legs: there is nothing to join, it is
            // already joined.
            total += 1.0;
            scored += 1;
            continue;
        }
        if entry.handles.is_empty() || entry.venue != "jpy" {
            continue;
        }
        let mine: Vec<&Vec<u8>> = entry.handles.iter().collect();
        let candidates: Vec<usize> = log.iter().enumerate()
            .filter(|(j, other)| *j != i && other.venue == "usd"
                    && other.call == entry.call
                    && other.handles.len() == mine.len()
                    && mine.iter().all(|h| other.handles.contains(h)))
            .map(|(j, _)| j)
            .collect();
        if candidates.is_empty() { continue; }
        // The true partner is the entry for the same swap. Uniform among the
        // candidates is the best this strategy can do.
        total += 1.0 / candidates.len() as f64;
        scored += 1;
    }
    let _ = count;
    if scored == 0 { 0.0 } else { total / scored as f64 }
}

fn main() {
    let mut rng = OsRng;
    let counts = [1usize, 2, 4, 8, 16];
    let repeats: usize = std::env::var("QOMM_BENCH_REPEATS").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(5);

    println!("two DeFMI deployments on one chain, {BITS}-bit rails\n");
    println!("{:<12} {:>6} {:>7} {:>6} {:>9} {:>9} {:>13} {:>13}",
             "arm", "swaps", "parties", "calls", "slots wr", "bytes wr",
             "verify ms", "observer");
    let mut rows = Vec::new();

    for distinct in [true, false] {
        for count in counts {
            for (name, run) in [("one transaction", one_transaction as fn(usize, bool, &mut OsRng) -> ArmResult),
                                ("adaptor", with_adaptor)] {
                let mut times = Vec::new();
                let mut last: Option<ArmResult> = None;
                for _ in 0..repeats {
                    let r = run(count, distinct, &mut rng);
                    times.push(r.verify_ms);
                    last = Some(r);
                }
                let r = last.unwrap();
                let t = Summary::of(&times).unwrap();
                let success = observer_success(&r.log, count);
                println!("{:<12} {:>6} {:>7} {:>6} {:>9} {:>9} {:>13} {:>12.3}",
                         name, count, if distinct { "distinct" } else { "one pair" },
                         r.calls, r.delta.slots_written, r.delta.bytes_written,
                         format!("{t}"), success);
                rows.push(format!(
                    "    {{\"arm\": \"{}\", \"swaps\": {}, \"parties\": \"{}\", \
                     \"calls\": {}, \"slots_written\": {}, \"bytes_written\": {}, \
                     \"verify_ms\": {{\"n\": {}, \"mean\": {:.4}, \"sd\": {}, \
                     \"median\": {:.4}}}, \"observer_success\": {:.4}, \
                     \"chance\": {:.4}}}",
                    name, count, if distinct { "distinct" } else { "one pair" },
                    r.calls, r.delta.slots_written, r.delta.bytes_written,
                    t.n, t.mean,
                    t.sd.map_or("null".into(), |v| format!("{v:.4}")), t.median,
                    success, 1.0 / count as f64));
            }
        }
        println!();
    }

    println!("`observer` is the chance a reader of the chain names the partner leg,");
    println!("using only what the calls expose. 1.000 means the two legs are joined");
    println!("without any cryptanalysis at all.");

    let Ok(path) = std::env::var("QOMM_BENCH_JSON") else { return };
    let json = format!(
        "{{\n  \"host\": \"{}\",\n  \"rustc\": \"{}\",\n  \"rail_bits\": {BITS},\n  \
         \"amount\": {AMOUNT},\n  \"repeats\": {repeats},\n  \
         \"observer\": \"joins two calls that name the same handles; guesses \
uniformly among the candidates\",\n  \"rows\": [\n{}\n  ]\n}}\n",
        std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| hosts::this_host()),
        shell("rustc", &["--version"]), rows.join(",\n"));
    std::fs::write(&path, json).expect("could not write the benchmark JSON");
    println!("\nwrote {path}");
}
