# DeFMI — a settlement layer that never reads the trade

Measured on `host-c` / Python 3.13.5 / group ed25519.
This document is generated from the measurement JSON by `make defmi-doc`. No number in it was typed by hand.

**Calibration**: scalar multiplication 37.3 ± 3.5 (n=50) us, 40-bit range proof 8.99 ± 0.17 (n=15) ms.
Every millisecond below is from a machine in that state. The same machine has been half again slower at another time, so compare these two figures before comparing anything else here with anything measured elsewhere.

## 1. What is guaranteed, and what is not

DeFMI can check only what arithmetic settles without opening anything.

| Guarantee | What makes it hold |
| --- | --- |
| Value is neither created nor destroyed | the product of the balance commitments equals the product at issue (homomorphism alone) |
| No balance goes negative | a range proof on the difference |
| The two legs move together | both are checked before either is applied |
| One instruction settles once | nullifier registration |
| Cash leg = quantity x price | a product proof over three commitments |
| The securities leg is the instructed quantity | an equality proof across generators |

What DeFMI does *not* check is whether the price was reasonable or whether that was the right instrument. Those meanings come from the computing nodes' quorum and travel in the instruction's signature. Making the settlement layer re-derive them would mean handing it the plaintext, which is the one thing this construction exists to avoid.

## 2. Cost depends on the balance width and nothing else

The proof is a bit decomposition of the ledger's balance range, so it should be linear. It is.

| balance width | issue instruction | build package | settle (verify) | package |
| ---: | ---: | ---: | ---: | ---: |
| 8 bit | 11.7 ± 0.2 (n=15) ms | 4.5 ± 0.1 (n=15) ms | 30.4 ± 0.4 (n=15) ms | 15,187 B |
| 16 bit | 11.9 ± 0.4 (n=15) ms | 8.0 ± 0.2 (n=15) ms | 34.8 ± 1.2 (n=15) ms | 18,771 B |
| 24 bit | 12.0 ± 0.3 (n=15) ms | 11.5 ± 0.2 (n=15) ms | 39.3 ± 0.4 (n=15) ms | 22,355 B |
| 32 bit | 12.3 ± 0.6 (n=15) ms | 15.6 ± 0.6 (n=15) ms | 47.5 ± 4.9 (n=15) ms | 25,939 B |
| 40 bit | 12.3 ± 0.9 (n=15) ms | 19.2 ± 1.3 (n=15) ms | 48.8 ± 2.0 (n=15) ms | 29,523 B |
| 48 bit | 12.0 ± 0.5 (n=15) ms | 22.1 ± 0.5 (n=15) ms | 52.3 ± 0.8 (n=15) ms | 33,107 B |

The slopes are **0.44 ms/bit** to build, **0.55 ms/bit** to settle and **448 B/bit** on the wire.
The settlement intercept, **26.1 ms**, is the part that does not depend on the ledger's width: it is the verification of the zkPI instruction itself.
At 40 bits, settlement costs 48.8 ± 2.0 (n=15) ms, of which about 53% is the instruction and the rest is the ledger's range proofs.

**Consequence**: if settlement needs to be faster, reconsidering the balance width beats changing the cryptography. That is a listing decision, not a technical one.

### 2.1 A different width for each rail

A quantity of securities and an amount of cash are orders of magnitude apart. There is no reason to give them the same width.

| securities rail | cash rail | build | settle | package |
| ---: | ---: | ---: | ---: | ---: |
| 48 bit | 48 bit | 34.0 ± 0.2 (n=15) ms | 52.4 ± 1.3 (n=15) ms | 33,107 B |
| 32 bit | 48 bit | 30.5 ± 0.3 (n=15) ms | 47.8 ± 0.3 (n=15) ms | 29,523 B |
| 24 bit | 48 bit | 29.5 ± 2.3 (n=15) ms | 45.6 ± 0.3 (n=15) ms | 27,731 B |
| 32 bit | 40 bit | 33.1 ± 3.3 (n=15) ms | 59.4 ± 11.8 (n=15) ms | 27,731 B |

Against both rails at 48 bits, running securities at 24 and cash at 48 settles **13% faster** and sends **5,376 B less**. Not one line of the cryptography changed.

## 3. Hiding which instrument, from the settlement layer too

The MPC layer hides which asset a request is for. Dropping the trade onto a per-instrument rail at settlement would give that back. Putting every instrument on one rail instead makes conservation hold only across instruments, so asset A could be carried out as asset B.

The construction used is an asset tag. Holding q units of asset a means holding `A_a^q . h^r`; each transfer publishes `H = A_a . h^y` under a fresh y, and every range proof is made against `H`. **What binds the disguise to a real asset is the range proof on the difference**: the payer's balance already sits under `A_a`, so no other tag can open it.

| instruments | set size | build, untagged | build, tagged | package | membership (at issue only) |
| ---: | ---: | ---: | ---: | ---: | --- |
| 4 | 4 | 18.9 ± 0.2 (n=15) ms | 19.0 ± 0.3 (n=15) ms | +32 B | prove 0.85 ± 0.06 (n=15) / verify 0.72 ± 0.04 (n=15) ms, 448 B |
| 16 | 16 | 18.9 ± 0.3 (n=15) ms | 19.0 ± 0.3 (n=15) ms | +32 B | prove 3.20 ± 0.12 (n=15) / verify 1.82 ± 0.07 (n=15) ms, 896 B |
| 64 | 64 | 18.7 ± 0.2 (n=15) ms | 19.0 ± 0.5 (n=15) ms | +32 B | prove 13.71 ± 0.51 (n=15) / verify 5.03 ± 0.21 (n=15) ms, 1344 B |

Every row of the untagged column runs the same work, so its own spread --- **0.2 ms** --- is this measurement's noise floor. The tagged column differs from it by +0.1 to +0.3 ms, which is **inside that floor**. So the honest statement is that the time cost is too small to measure here; a percentage would mislead. Only the extra bytes are certain.

Per settlement the addition is **32 B** (one published tag) and one sigma proof across generators. The one-out-of-many membership proof (Groth-Kohlweiss) is not needed every time: a balance already sitting under a registered tag passes soundness down to the transfer, so the proof is needed **once, when the balance is issued into the account**.

Indistinguishability and the attack arms, measured:

- 4 instruments: the package is identical whichever one it is (identical, 29,555 B across 4 instruments).
  - carry it out under a registered tag for another asset: `rejected` --- securities leg: remainder does not equal balance minus amount
  - use a point that was never registered: `rejected` --- securities leg: remainder does not equal balance minus amount
- 16 instruments: the package is identical whichever one it is (identical, 29,555 B across 8 instruments).
  - carry it out under a registered tag for another asset: `rejected` --- securities leg: remainder does not equal balance minus amount
  - use a point that was never registered: `rejected` --- securities leg: remainder does not equal balance minus amount
- 64 instruments: the package is identical whichever one it is (identical, 29,555 B across 8 instruments).
  - carry it out under a registered tag for another asset: `rejected` --- securities leg: remainder does not equal balance minus amount
  - use a point that was never registered: `rejected` --- securities leg: remainder does not equal balance minus amount

## 4. Netting: gross-gross, gross-net, net-net

These are the BIS DvP models 1, 2 and 3. They are a question about settlement design and, at the same time, a question about **how many range proofs land and where**.

A rail is either gross or net, and that single choice decides everything else.

- **A gross rail** checks at each order. It proves on the spot that the post-trade position is non-negative, so **settlement failure cannot occur by construction**. The price is order dependence: a participant receiving 100 and delivering 100 is refused if the delivery arrives first. That deliberately gives up the liquidity saving netting exists to provide.
- **A net rail** only accumulates homomorphically during the period and proves nothing. A commitment hides the sign as well as the magnitude, so an intermediate position may be negative without leaking anything --- what is not proved is not disclosed. At the close it shows coverage once per participant, on the **net**. The liquidity saving comes back and order dependence goes away, at the cost of a close that can fail.

| N | P | mode | verify per order | verify at close | verify total | vs gross-gross |
| ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 16 | 8 | gross-gross | 51.73 ± 6.23 (n=3) ms | 0.3 ± 0.0 (n=3) ms | 827.9 ± 99.6 (n=3) ms | 1.00x |
| 16 | 8 | gross-net | 37.00 ± 0.11 (n=3) ms | 87.9 ± 0.6 (n=3) ms | 679.9 ± 2.3 (n=3) ms | 1.22x |
| 16 | 8 | net-net | 27.58 ± 2.01 (n=3) ms | 181.8 ± 9.6 (n=3) ms | 623.1 ± 41.8 (n=3) ms | 1.33x |
| 16 | 8 | net-net+attested | 0.04 ± 0.00 (n=3) ms | 197.8 ± 27.0 (n=3) ms | 198.5 ± 27.0 (n=3) ms | 4.17x |
| 64 | 8 | gross-gross | 50.67 ± 1.78 (n=3) ms | 0.2 ± 0.0 (n=3) ms | 3243.0 ± 114.0 (n=3) ms | 1.00x |
| 64 | 8 | gross-net | 38.72 ± 1.46 (n=3) ms | 95.3 ± 9.2 (n=3) ms | 2573.2 ± 101.4 (n=3) ms | 1.26x |
| 64 | 8 | net-net | 26.47 ± 0.46 (n=3) ms | 176.9 ± 1.3 (n=3) ms | 1871.0 ± 28.1 (n=3) ms | 1.73x |
| 64 | 8 | net-net+attested | 0.04 ± 0.00 (n=3) ms | 178.2 ± 2.7 (n=3) ms | 180.7 ± 2.7 (n=3) ms | 17.95x |

**The first prediction was wrong.** Counting range proofs alone gave an estimate that net-net would be an eighth of the work; measured, it is only 1.73x. Even under net-net, 26.5 ± 0.5 (n=3) ms per order remains, and that is the verification of the zkPI instruction itself --- which carries range proofs on amount and price inside it. **It is needed once per trade and netting does not remove it.**

What removes it is changing the **granularity of the instruction**. If the quorum signs a whole cycle rather than each trade, the settlement layer's work stops depending on the number of trades (0.04 ± 0.00 (n=3) ms per order, 180.7 ± 2.7 (n=3) ms in total, **18.0x**). The individual trades are then no longer verified, so the allocation between participants becomes **the quorum's attestation rather than a proof**. Conservation and coverage still hold, and each participant can check its own net, so what is lost is third-party verifiability of the allocation. That is what a central counterparty has always been; this only makes it explicit.

### 4.1 How far a net position may go (an intraday overdraft)

Refusing any order that would make a net position negative removes settlement failure, and, as above, removes the liquidity saving with it. Practice puts a **limit** here instead --- the Bank of Japan's intraday overdraft is exactly this: eligible collateral is pledged, a limit is granted up to its value after haircut, and the position may be negative down to that limit.

The limit is a **commitment**, and not only to hide its size. Coverage is then proved about `position + limit`, which means the proof **never says which side of zero the position was on**. The offset trickery that hiding a sign usually needs is not needed anywhere.

| operation | cost | how often |
| --- | ---: | --- |
| grant a limit (proving the collateral covers it after haircut) | build 13.0 ± 0.4 (n=15) / verify 15.2 ± 0.5 (n=15) ms | once per limit |
| coverage proof, no limit | 9.4 ± 0.3 (n=15) ms | per participant per rail, at the close |
| coverage proof, with a limit | 9.5 ± 0.2 (n=15) ms | as above |

**The limit is essentially free** (9.4 ± 0.3 (n=15) to 9.5 ± 0.2 (n=15) ms --- the same range proof width against a different commitment). Admission, pledge, overdraft and payment are handled as one event by `admit_with_credit`, because doing them in sequence allows either collateral locked with no limit granted or a limit standing with no collateral behind it. If the payment does not go through, the limit and the pledge are both rolled back.

### 4.2 The default waterfall

A net rail can fail at the close. The order in which that failure is worked through is the substance of the arrangement, so it has to be **enforced** and not assumed. The condition that tranche k may be drawn only once tranche k-1 is exhausted is written `draw_k x remaining_{k-1} = 0`. The product's commitment is pinned to the identity, so there is nothing to hand the verifier.

| tranches | build | verify |
| ---: | ---: | ---: |
| 2 | 27.6 ± 0.7 (n=15) ms | 33.5 ± 0.6 (n=15) ms |
| 4 | 46.0 ± 0.7 (n=15) ms | 56.0 ± 1.0 (n=15) ms |
| 8 | 87.2 ± 6.3 (n=15) ms | 105.8 ± 7.4 (n=15) ms |
| 16 | 159.9 ± 5.2 (n=15) ms | 194.7 ± 7.3 (n=15) ms |

**9.5 ms per tranche** --- one range proof's worth, linear. It runs once per default, so nobody need ever care about this number.

## 5. Hiding who paid whom (the note ledger)

The asset tag hides *what*. An account ledger still names four handles in the clear at every settlement. Even with every balance committed, handles that recur draw the counterparty graph.

So accounts were replaced by notes. A note is `C = g^S . A_a^v . h^r`, where only the **payee** can construct S --- the sender can form `g^S` from the public key but does not know the b in S = H(A^e) + b. Spending keeps S hidden and shows with Groth-Kohlweiss that **one of** the ring holds this S, without saying which.

| ring size | prove (payer) | verify (node) | wire |
| ---: | ---: | ---: | ---: |
| 2 | 19.1 ± 0.3 (n=15) ms | 22.6 ± 0.2 (n=15) ms | 18,784 B |
| 4 | 20.1 ± 0.4 (n=15) ms | 23.7 ± 0.5 (n=15) ms | 19,008 B |
| 8 | 20.8 ± 0.4 (n=15) ms | 24.0 ± 0.4 (n=15) ms | 19,232 B |
| 16 | 22.2 ± 0.5 (n=15) ms | 24.3 ± 0.5 (n=15) ms | 19,456 B |
| 32 | 26.2 ± 0.9 (n=15) ms | 26.1 ± 0.7 (n=15) ms | 19,680 B |
| 64 | 33.5 ± 0.9 (n=15) ms | 28.2 ± 0.8 (n=15) ms | 19,904 B |
| 128 | 49.8 ± 1.5 (n=15) ms | 32.5 ± 0.7 (n=15) ms | 20,128 B |
| 256 | 85.6 ± 1.5 (n=15) ms | 40.9 ± 0.7 (n=15) ms | 20,352 B |
| 512 | 164.7 ± 3.5 (n=15) ms | 57.8 ± 0.8 (n=15) ms | 20,576 B |

**The asymmetry is the point.** The wire grows by 224 B per doubling, and verification only goes from 22.6 ± 0.2 (n=15) to 57.8 ± 0.8 (n=15) ms between rings 2 and 512. What breaks is the proving side: 19.1 ± 0.3 (n=15) to 164.7 ± 3.5 (n=15) ms.
So **what caps the anonymity set is the payer, not the settlement node**. A ring of 64 costs 33.5 ± 0.9 (n=15) ms to prove and 28.2 ± 0.8 (n=15) ms to verify, which a payer's own device can carry.

A payee has to scan the pool to find its own notes, at **0.055 ms** each (28.2 ms over 512). That is one scalar multiplication, and it is the only cost proportional to the pool.
Two payments to the same address cannot be linked: **True** (neither the commitments nor the ephemeral points match).

### 5.1 The same DvP over note rails

Both rails were made note rails and the settlement itself was run through them. The binding to the instruction is kept by a single equality proof across generators, because the quantity is committed under the tag and the instruction under the base.

| ring size | build | settle (verify) | package | vs the account version |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 49.7 ± 9.7 (n=5) ms | 88.6 ± 13.1 (n=5) ms | 49,547 B | +82% |
| 4 | 53.9 ± 16.9 (n=5) ms | 82.9 ± 14.9 (n=5) ms | 50,123 B | +70% |
| 8 | 42.7 ± 0.2 (n=5) ms | 75.2 ± 1.2 (n=5) ms | 50,827 B | +54% |
| 16 | 46.8 ± 1.1 (n=5) ms | 80.8 ± 7.3 (n=5) ms | 51,787 B | +66% |
| 32 | 55.1 ± 4.1 (n=5) ms | 82.1 ± 7.6 (n=5) ms | 53,259 B | +68% |
| 64 | 67.0 ± 0.6 (n=5) ms | 83.9 ± 0.5 (n=5) ms | 55,755 B | +72% |

The account version settles in 48.8 ± 2.0 (n=15) ms at 40 bits. Hiding the counterparties costs +82% at ring 2 and +72% at ring 64.
**Adding up the parts was off by more than a factor of two.** A note leg and an account leg both carry two range proofs; the difference is only the ring proof, the serial proof and one equality proof.

## 6. What one settlement node can take

Verification only --- proving is the counterparty's work and the clock is stopped for it. Every worker meets at a barrier before the measured section begins.

| workers | settlements/s | vs one worker |
| ---: | ---: | ---: |
| 1 | 21.0 ± 0.0 (n=7) | 1.00x |
| 2 | 41.8 ± 0.1 (n=7) | 1.99x |
| 4 | 81.9 ± 1.3 (n=7) | 3.91x |
| 8 | 157.0 ± 3.6 (n=7) | 7.49x |

Verifications of independent packages share nothing, so they parallelise completely: **157 per second** on 8 workers. A settlement node's capacity is a procurement question, not a design one.

A second host with more cores (`host-a`, 64 logical cores) was measured too. Its calibration is 68.3 us per scalar multiplication against 37.3 us here, so it is **1.83x slower per core**. Its single-worker throughput differs by 1.83x (21.0 to 11.5 per second), which is the same ratio by an independent route.

| workers | settlements/s | vs one worker | vs linear |
| ---: | ---: | ---: | ---: |
| 1 | 11.5 | 1.00x | 100% |
| 2 | 22.9 | 2.00x | 100% |
| 4 | 45.8 | 4.00x | 100% |
| 8 | 91.4 | 7.98x | 100% |
| 16 | 181.7 | 15.86x | 99% |
| 32 | 364.7 | 31.83x | 99% |
| 64 | 688.6 | 60.10x | 94% |

**689 per second** on 64 workers, only 6% short of linear. Nothing is shared between verifications, so this shape is what was expected.

## 7. The Rust port

Measured on the same machine (`host-c` / rustc 1.97.1 (8bab26f4f 2026-07-14) / group ristretto255). The scalar-multiplication calibration is 37.4 us in Rust against 37.3 us in Python, and **this one figure is the only thing that compares across the two languages** --- Python goes through libsodium and Rust through dalek, different implementations of the same thing: a scalar multiplication on a native-code 255-bit curve. That they agree says the two are equally fast and, more usefully, that **the machine was in the same state**, which is what stops the ratios below being explained by the machine.

What is being compared is not only the language. The port also replaced a hand-rolled bit-decomposition range proof with the audited `bulletproofs` crate, so **the ratios below are 'became Rust' and 'became Bulletproofs' added together**. The order-of-magnitude change on the wire is the second of those: linear became logarithmic.

| balance width | Python settle | Rust settle | ratio | Python package | Rust package | ratio |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 bit | 30.4 ± 0.4 (n=15) ms | 2.09 ms | 14.6x | 15,187 B | 2,240 B | 6.8x |
| 16 bit | 34.8 ± 1.2 (n=15) ms | 2.93 ms | 11.9x | 18,771 B | 2,432 B | 7.7x |
| 32 bit | 47.5 ± 4.9 (n=15) ms | 4.56 ms | 10.4x | 25,939 B | 2,624 B | 9.9x |

Bulletproofs only comes in powers of two, so a 40-bit rail **rounds up to 64**. Comparing against the rounded-up side is the honest comparison: 48.8 ± 2.0 (n=15) ms for Python at 40 bits against 7.36 ms for Rust at 64, **6.6x**. The package goes from 29,523 to 2,816 B, **10.5x**.

Per core that is 20.5 to 135.8 settlements per second. Parallelism is independent, so multiply by cores.

**Losing the fine grain of the width is a real cost.** A bit decomposition could prove 24 or 40 bits directly, which is what made the per-rail width optimisation of section 2.1 work. With only powers of two, securities at 24 bits round up to 32 and cash at 40 to 64. The conclusion here is that the table above is still a large enough difference to swallow that.

## 8. What is still missing

- The cash rail carries no tag, because hiding *which cash* means nothing with a single settlement currency. Making it multi-currency is the same construction applied once more, but it is neither built nor measured.
- Whoever sent a note can tell that it was spent, because they know the `g^S` they built. That is unavoidable in this construction. To a third party the ring size is the limit of what is learned.
- Collateral is handled as an already-valued amount. Turning pledged securities into a valuation --- quantity x price, against a price the quorum signed --- is not implemented, and a deployment where collateral and credit are different assets needs it.
- The Rust side has no note-rail DvP (`note_settlement`). The account rail, netting, credit and notes on their own are ported; the measurement in section 5.1 exists only in Python.
- Working a waterfall through to the ledger is not wired up. It proves and verifies; writing the tranches down is still the caller's job.
