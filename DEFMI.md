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

### 4.2 Interposing a clearing house, and what novation is worth

The paragraph above ends by calling the batch attestation "the same bargain a central counterparty represents, made explicit". That was one step short. **Under novation there is no split left to verify**, because there are no bilateral claims left to split: a trade between A and B becomes A against the house and the house against B, and the original obligation stops existing. Verifying an allocation that has been extinguished is not a check anybody was owed.

And novation is free here. An obligation is a commitment, so replacing one edge with two is two multiplications and no proof --- nothing is being asserted, the graph is being rewritten. The house's book is flat by the same construction: it owes exactly what it is owed, per asset, so that is one comparison rather than a statement anybody has to establish.

Measured at 8 participants, against the two arms above run by the same harness:

| trades | net-net | net-net+attested | **DeCCP** | vs net-net | novation |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 369.3 ± 4.5 (n=3) | 174.1 ± 2.5 (n=3) | **175.6 ms** | **2.09x** | 14.96 us/trade |
| 64 | 946.8 ± 8.2 (n=3) | 173.2 ± 2.5 (n=3) | **174.0 ms** | **5.43x** | 16.15 us/trade |
| 256 | 3258.0 ± 12.1 (n=3) | 178.4 ± 0.3 (n=3) | **186.7 ms** | **17.44x** | 15.98 us/trade |

**net-net grows with the trades and DeCCP does not.** From 16 to 256 trades the instruction path goes 367 ms to 3256 ms while the cleared cycle goes 176 ms to 187 ms. What is left is the close, and the close is per participant.

So the speed was never the contribution --- the attested arm already had it. **What novation costs is 15.98 us a trade, and what it buys is that the arm is defensible**: a named house took the other side, its book is checked flat by anyone, its margin is posted as a committed cap, and its own capital sits in the default waterfall between the defaulting member's fund contribution and the mutualised pool, which is where CPMI-IOSCO and EMIR put it.

A slot rather than a dependency. A deployment names the providers it accepts and several may coexist; nothing in the netting cycle or the settlement layer knows which house cleared a trade, and a deployment with no provider at all is the bilateral case, which still works and pays per-trade proofs for it.

**Four things it does not do.** Obligation graphs are per asset, so a novation that mixed instruments is refused rather than netted across them. Several providers make the waterfall a forest and not a list, and a position at one provider is **not** offset against a position at another --- cross-margining is a different problem and is not solved here. Novation being free arithmetically says nothing about it being valid legally, which is the register's rulebook and not this code. And **the trade set is attested, not verified**: a house that novated trades nobody made would produce a cycle that checks out, which a test states outright. The arithmetic cannot tell. The tranche is what makes getting it wrong expensive.

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

### 5.2 What the ring is actually worth

*Taken on `host-a`.*

Every table above prices the ring. None of them asks what it buys, and the answer has been the ring size --- an observer who knows a leg spent one of R notes names it with probability 1/R. That is what the proof guarantees and it is not what a reader of the chain gets.

A ring is an anonymity set only if the decoys are indistinguishable from the real note. `ring_for` drew its decoys uniformly over every note the ledger had ever held. A real spend is of a note the spender was just paid, because that is what settling is --- you are paid, and then you pay. Recent notes have high indices and uniform decoys mostly do not, so **an observer who guesses the newest member of the ring** does far better than 1/R and pays nothing for it.

The strategy was stated before the run and the observer is scored at the better of the two, because a real one would take it. `traffic` is how many other settlements land between one firm being paid and paying: the pool grows by four notes a settlement, so it is other people's activity, measured in notes that arrive above yours.

| decoys | ring | traffic 0 | traffic 4 | traffic 16 | 1/R |
| --- | ---: | ---: | ---: | ---: | ---: |
| uniform | 4 | 1.000 | 0.844 | 0.781 | 0.250 |
| uniform | 8 | 1.000 | 0.750 | 0.594 | 0.125 |
| uniform | 16 | 1.000 | 0.547 | 0.359 | 0.062 |
| recent | 4 | 1.000 | 0.469 | 0.250 | 0.250 |
| recent | 8 | 1.000 | 0.188 | 0.125 | 0.125 |
| recent | 16 | 1.000 | 0.062 | 0.062 | 0.062 |

**With no other traffic the ring is worth nothing at all** --- 1.000 at every size, under either rule, because a note spent one settlement after it arrived is the newest note there is and no decoy can be newer than the newest. That is not a decoy-selection bug; it is the honest shape of the thing:

> an anonymity set on a note rail is other people's traffic, and the decoy rule only decides how much of it the ring can use.

Which is the same shape as §6.1 below. A construction that hides you in a crowd does not work in an empty room, and saying so is part of reporting what it does.

What the decoy rule is worth is the gap between the two blocks. At ring 16 with 16 settlements of other traffic, uniform decoys leave the observer at **0.359** against a nominal 0.062 --- 5.8 times what the proof promises. Drawing the decoys from the same recency window that real spends come from brings it to **0.062**, which is the nominal figure exactly. `ring_recent` is that rule and it is thirty lines.

### 5.3 A settlement that got slower the longer the ledger ran

The benchmark above found something that is not about rings. Its verification times climbed with the pool, and nothing in `check_spend` is proportional to the pool --- the ring proof, the range proofs and the balance check are all in the ring. What was proportional to it was the **state root**: `snapshot` compressed every note the ledger had ever held and re-sorted every spent serial, and a settlement takes four of them, two rails before and after.

| notes held | root by walking | root as kept | |
| ---: | ---: | ---: | ---: |
| 64 | 238.4 ± 2.4 (n=9) us | 0.19 ± 0.11 (n=9) us | 1,263x |
| 256 | 949.3 ± 2.3 (n=9) us | 0.21 ± 0.17 (n=9) us | 4,480x |
| 1,024 | 3800.0 ± 5.0 (n=9) us | 0.13 ± 0.03 (n=9) us | 28,788x |
| 4,096 | 15187.3 ± 16.0 (n=9) us | 0.16 ± 0.01 (n=9) us | 95,278x |

At 4,096 notes the four roots in one settlement came to **60.7 ms**, against about 8 ms of cryptography --- the bookkeeping had become an order of magnitude more expensive than the proofs, and it would keep growing, because it was a function of total history rather than of activity. That is the exact property §7 checks for the account rail and it had gone unchecked here.

Nothing about the ledger required it. Notes are only ever appended --- a spent note stays in the pool, because removing it would say which one went --- and serials are only ever inserted, so the hash of the whole history is a running hash extended once per change. The sort was buying order-independence for a sequence that already has an order: the one the chain applied. The root is now kept rather than recomputed and the column above is flat.

## 6. Payment versus payment, across two ledgers

*The two tables in this section were taken on `host-a`, not the `host-c` of the rest of this document: they are Rust benchmarks and they wanted a machine that was not doing anything else.*

DvP moves two legs together because both are on one ledger and one function decides. Two ledgers that share no state have no such function, and fair exchange between two parties with no third party is impossible in general --- so something has to pass from one side to the other. The only question is what, and who can read it.

A hash lock passes a preimage that ends up in the clear on both ledgers, so anyone reading both can join the two legs on it. That is the linkage the asset tag and the note ledger were built to prevent, handed back at the last step. What is used instead is an **adaptor signature**: the first mover's claim on one ledger hands the second mover a scalar, and what each ledger records is an ordinary signature with nothing in common with the other's.

```
1. Bob   -> Alice : Y = g^y
2. Alice           prepares leg A; her money leaves her account
   Alice -> Bob   : a pre-signature over "leg A", adapted to Y
3. Bob             prepares leg B, and sends his own pre-signature
4. Bob             claims on A  -> he is paid, and y becomes readable
5. Alice           reads A, recovers y, claims on B  -> she is paid
```

Bob draws the secret and moves first, so Bob is never at risk: if he stops after step 3 both escrows expire and both parties are whole. Alice is exposed in exactly one window, between step 4 and step 5, and she is safe if and only if the gap between the two deadlines covers her reaction. **That gap is this arrangement's Herstatt risk**, and it is the number worth measuring.

| | measured, 32-bit rails |
| --- | ---: |
| prepare one leg (check, and move it out of reach) | 1.28 ± 0.01 ms (n=25) |
| the first mover's claim | 0.05 ± 0.00 ms (n=25) |
| **the second mover's reaction** | **0.06 ± 0.00 ms (n=25)** |
| unwind an expired leg | 0.63 ± 0.04 us (n=25) |

**The cryptography is not what puts the money at risk.** Recovering the secret, adapting the signature and having the second ledger accept it comes to 0.06 ms. The deadline gap has to cover that *plus* the time for one ledger to publish the first claim and the other to accept the second --- block times and network round trips, which are three to five orders of magnitude larger. So the exposure is set by the settlement finality of the two ledgers and not by anything in this repository, and a deployment that wants a short window should shop for finality rather than for faster proofs.

Preparing costs about what a transfer costs, because that is what it is: the same check, with the amount moved into an escrow instead of into the payee. Unwinding costs nothing, and deliberately requires no signature --- the deadline is the whole authority, because demanding a signature would strand the money of anyone who lost a key, which is the failure this branch exists to prevent.

### 6.1 On one chain, and what the unlinkability actually rests on

*Taken on `host-a`.*

Across two chains there is no choice about atomicity: nothing spans them, so an adaptor signature and a deadline are the only way. On one chain --- two DeFMI deployments, two contract addresses --- there is a choice. A single transaction calling both venues gets atomicity from the chain for nothing and its exposure window is zero, but that transaction is the link. Two transactions with an adaptor keep the legs cryptographically unrelated and pay at least one block.

What the second arm costs is small and flat:

| at 16 swaps | one transaction | adaptor |
| --- | ---: | ---: |
| calls | 16 | 64 |
| state slots written | 96 | 128 |
| bytes written | 3328 | 3072 |
| verification | 282.2 ± 0.2 (n=5) ms | 291.8 ± 0.3 (n=5) ms |
| exposure window | none | at least one block |

Four times the calls and a third more state slots --- holding **fewer bytes** in them, because a settlement records a nullifier and a deadline (40 bytes a venue) where the escrow path records neither: the escrow key is itself the replay guard, and it costs a slot rather than bytes --- for **3.4% more verification** (+3.0% to +3.8% across the table). The range proofs dominate, and the escrow and the signature are a few percent beside them rather than nothing at all: this is a difference the earlier run on a loaded machine could not resolve: both arms read 413 ms there, with standard deviations of 9 and 20 ms against a gap that should have been about 14. It was not measured to be zero; it was not measurable.

What it buys is the question, and the answer turned out to depend on something that was not cryptography at all.

**What a reader of the chain can still join**, using nothing but what the calls name. One stated strategy, run over the real records: take a call on one venue, find the calls on the other that name the same handles, guess uniformly among them; where no handle matches, guess uniformly among all of them.

| naming | swaps in flight | between | one transaction | adaptor | chance |
| --- | ---: | --- | ---: | ---: | ---: |
| a handle per venue | 1 | distinct | 1.000 | **1.000** | 1.000 |
| a handle per venue | 2 | distinct | 1.000 | **0.500** | 0.500 |
| a handle per venue | 4 | distinct | 1.000 | **0.250** | 0.250 |
| a handle per venue | 8 | distinct | 1.000 | **0.125** | 0.125 |
| a handle per venue | 16 | distinct | 1.000 | **0.062** | 0.062 |
| a handle per venue | 1 | one pair | 1.000 | **1.000** | 1.000 |
| a handle per venue | 2 | one pair | 1.000 | **0.500** | 0.500 |
| a handle per venue | 4 | one pair | 1.000 | **0.250** | 0.250 |
| a handle per venue | 8 | one pair | 1.000 | **0.125** | 0.125 |
| a handle per venue | 16 | one pair | 1.000 | **0.062** | 0.062 |
| one name everywhere | 1 | distinct | 1.000 | **1.000** | 1.000 |
| one name everywhere | 2 | distinct | 1.000 | **1.000** | 0.500 |
| one name everywhere | 4 | distinct | 1.000 | **1.000** | 0.250 |
| one name everywhere | 8 | distinct | 1.000 | **1.000** | 0.125 |
| one name everywhere | 16 | distinct | 1.000 | **1.000** | 0.062 |
| one name everywhere | 1 | one pair | 1.000 | **1.000** | 1.000 |
| one name everywhere | 2 | one pair | 1.000 | **0.500** | 0.500 |
| one name everywhere | 4 | one pair | 1.000 | **0.250** | 0.250 |
| one name everywhere | 8 | one pair | 1.000 | **0.125** | 0.125 |
| one name everywhere | 16 | one pair | 1.000 | **0.062** | 0.062 |

**The privacy of this construction was sitting in a naming convention.** With one identifier at both venues --- which is what a caller reaches for, and what this benchmark did on its first run --- the adaptor buys nothing between distinct parties: a prepare is a transfer, a transfer says who is paying whom, and joining "this firm pays here" to "this firm is paid there" needs no cryptanalysis. Four times the calls for a number that does not move.

With a handle derived per venue --- `qomm_zkpi::handles`, one seed and an unrelated point at each venue --- the adaptor delivers exactly what it promises: the observer falls to chance, 1/k, and stays there whether the swaps are between distinct parties or the same pair. Nothing about the cryptography changed between those two blocks of the table. Only the names did.

This is worth stating plainly because the property was written down as prose before it was code, and prose does not hold. The design said handles are derived per venue so that one firm is two unrelated points; the library offered no way to derive them, so the obvious integration was the one that loses. It is code now, and the test that goes with it runs the scheme that suggests itself first --- one secret scaled by a public per-venue factor --- and shows it is publicly linkable.

Two things the table is not. The observer here is given **no timing**: every prepare is placed in one block, so a real observer watching them arrive does better than 1/k. And these are account rails. The note ledger of §5 removes the handle rather than deriving it well, which sounds like the stronger answer and is, but §5.2 measured what it is worth and the two findings are the same one: **both constructions hide you in other people's traffic and neither does anything without it.** A ring with no other settlements around it names its note with certainty, exactly as an adaptor with one swap in flight names its partner leg. What differs is the exchange rate --- how much traffic each one needs to buy a given amount of doubt --- and not whether traffic is what is being spent.

This measurement first ran against a version where the property was the caller's to keep. The instruction named two handles and the package named four accounts, and nothing compared them --- so a caller who derived handles per venue and then opened accounts under one name everywhere got the losing row of the table while believing it had the winning one. That is now closed: the four account names are **derived from the two signed handles** (`Sides::of`, one hash of the handle and the rail), `build_package` no longer takes them as an argument, and a package whose accounts disagree with its instruction is rejected before any proof is examined. The per-venue property is enforced where it is used rather than assumed of the caller.

## 6.5 Agreeing with the book of record

Under Japan's book-entry regime this ledger cannot *be* the register: title rests on the record the transfer agent and the account management institutions keep. So it is a mirror, and reconciliation is not a feature but the price of that arrangement.

It is one line of algebra. Commitments multiply, so the product of the balances is a commitment to their sum; divide out the register's figure under the asset tag and what remains must be a pure power of `h`. Proving knowledge of that exponent proves the totals agree and says nothing else --- **no balance opens, and the total was the register's own number**.

| positions | prove | check | quorum assembles |
| ---: | ---: | ---: | ---: |
| 16 | 0.25 ± 0.02 (n=7) | 0.30 ± 0.01 (n=7) | 1.29 ± 0.01 (n=7) (3 of 7) |
| 64 | 0.61 ± 0.02 (n=7) | 0.65 ± 0.03 (n=7) | 1.60 ± 0.06 (n=7) (3 of 7) |
| 256 | 2.04 ± 0.05 (n=7) | 2.04 ± 0.03 (n=7) | 3.04 ± 0.02 (n=7) (3 of 7) |
| 1,024 | 7.79 ± 0.06 (n=7) | 7.81 ± 0.12 (n=7) | 8.55 ± 0.08 (n=7) (3 of 7) |
| 4,096 | 34.77 ± 2.82 (n=7) | 30.15 ± 0.30 (n=7) | 31.02 ± 0.27 (n=7) (3 of 7) |

Linear in the positions and nothing else: at 4,096 it is 30.2 ± 0.3 (n=7) to check, and the proof on the wire is 96 B whatever the ledger holds.

The **quorum** column is the same statement assembled by nodes holding shares of the aggregate blinding, so nobody holds the sum --- which matters, because whoever holds it could open the whole ledger. A sigma response is affine in the witness, so the partials combine into an ordinary proof any verifier accepts.

### 6.5.1 A break is pass or fail, and looking costs disclosure

If the totals disagree the proof does not verify, and that is all anyone learns. Finding *where* needs somebody to claim subtotals, and every subtotal claimed becomes public --- the narrowest of them covers one position, which is a balance. **This is the only operation in DeFMI that discloses on purpose, and it is the operation you reach for on the day something is wrong.**

| positions | sub-range proofs | 2 log2 n + 1 | subtotals made public | narrowest |
| ---: | ---: | ---: | ---: | ---: |
| 16 | 9 | 9 | 9 | 1 position |
| 64 | 13 | 13 | 13 | 1 position |
| 256 | 17 | 17 | 17 | 1 position |
| 1,024 | 21 | 21 | 21 | 1 position |
| 4,096 | 25 | 25 | 25 | 1 position |

A register that holds **a figure per position** rather than one for the account localises for free and discloses nothing: an account management institution already holds the mapping from handle to book-entry account, so it holds the openings and the check is arithmetic on numbers it has. At 4,096 positions that is 322.2 ms.

**Reconciling is the cheap half and the search is not.** Which one you are in depends on what the register keeps, which is a question about the counterparty and not about this ledger.

## 6.6 Showing an auditor one slice

A note wallet is a view key and a spend key, and the view key was always described as the one you could hand an auditor. You could, and that was the whole of it: one key, so handing it over gives every instrument, every period, permanently, with no way back.

The scoping is not in the key. It is in the **address**. A scope --- an instrument, a quarter, a mandate --- derives its own pair of scalars from the wallet's seeds by hashing, so it has its own address, and notes sent there are found by that scope's view key and by nothing else. The derivation is one way, so a scope says nothing about the seed or about a sibling. The note construction, the scan and the spend are all unchanged; what changes is which address a payer is given.

| pool | scan | per note | reached | exactly its scope | serials recovered |
| ---: | ---: | ---: | ---: | :---: | ---: |
| 64 | 3.8 ± 0.1 (n=5) | 0.0576 ms | 13 of 64 (20.3%) | yes | 0 |
| 256 | 15.4 ± 0.2 (n=5) | 0.0591 ms | 52 of 256 (20.3%) | yes | 0 |
| 1,024 | 60.8 ± 0.7 (n=5) | 0.0585 ms | 205 of 1,024 (20.0%) | yes | 0 |

The scan is one scalar multiplication a note, the same as a wallet scanning for itself, at 0.0585 ms. With 4 scopes in the pool plus a stranger's notes the holder reaches about a fifth of it, which is the fifth it was granted --- and **no serial numbers at all**, because a serial needs the spend key and the grant does not carry one.

A grant is 0.04 ± 0.00 (n=15) to issue and 0.05 ± 0.00 (n=15) to check. It names the grantee and is signed by the wallet, so a key found somewhere it should not be traces to the grant that produced it --- attribution rather than prevention, the same trade `roles.py` makes about a dealt share.

### 6.6.1 Three limits that do not go away

**A grant cannot be taken back.** Whoever holds a scope's key can read every note ever sent to that address and every one that ever will be. An expiry stops a party that chooses to be stopped and nothing else. What actually revokes is moving to the next scope, because the next scope is a different address --- so revocation is an act of address management and not a message.

**A view key is incoming only.** It finds what arrived and cannot see what the wallet spent: spending publishes a serial and a ring, and neither is derivable from the view key. An auditor that needs outflows needs the wallet to hand over its serials, which is a different disclosure than this one.

**Scoping is only as fine as the payers cooperate.** A scope exists because counterparties were told to pay to that address; one who uses last quarter's address puts the note in last quarter's scope and nothing in the protocol stops them. That is an operational control wearing a cryptographic coat, and it is worth knowing which it is.

## 7. What one settlement node can take

Verification only --- proving is the counterparty's work and the clock is stopped for it. Every worker meets at a barrier before the measured section begins.

| workers | settlements/s | vs one worker |
| ---: | ---: | ---: |
| 1 | 21.0 ± 0.0 (n=7) | 1.00x |
| 2 | 41.8 ± 0.1 (n=7) | 1.99x |
| 4 | 81.9 ± 1.3 (n=7) | 3.91x |
| 8 | 157.0 ± 3.6 (n=7) | 7.49x |

Verifications of independent packages share nothing, so they parallelise completely: **157 per second** on 8 workers. A settlement node's capacity is a procurement question, not a design one.

## 8. The Rust port

Measured on the same machine (`host-c` / rustc 1.97.1 (8bab26f4f 2026-07-14) / group ristretto255). The scalar-multiplication calibration is 35.8 us in Rust against 37.3 us in Python, and **this one figure is the only thing that compares across the two languages** --- Python goes through libsodium and Rust through dalek, different implementations of the same thing: a scalar multiplication on a native-code 255-bit curve. That they agree says the two are equally fast and, more usefully, that **the machine was in the same state**, which is what stops the ratios below being explained by the machine.

What is being compared is not only the language. The port also replaced a hand-rolled bit-decomposition range proof with the audited `bulletproofs` crate, so **the ratios below are 'became Rust' and 'became Bulletproofs' added together**. The order-of-magnitude change on the wire is the second of those: linear became logarithmic.

| balance width | Python settle | Rust settle | ratio | Python package | Rust package | ratio |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 bit | 30.4 ± 0.4 (n=15) ms | 2.16 ms | 14.1x | 15,187 B | 2,240 B | 6.8x |
| 16 bit | 34.8 ± 1.2 (n=15) ms | 3.04 ms | 11.5x | 18,771 B | 2,432 B | 7.7x |
| 32 bit | 47.5 ± 4.9 (n=15) ms | 4.85 ms | 9.8x | 25,939 B | 2,624 B | 9.9x |

Bulletproofs only comes in powers of two, so a 40-bit rail **rounds up to 64**. Comparing against the rounded-up side is the honest comparison: 48.8 ± 2.0 (n=15) ms for Python at 40 bits against 7.79 ms for Rust at 64, **6.3x**. The package goes from 29,523 to 2,816 B, **10.5x**.

Per core that is 20.5 to 128.5 settlements per second. Parallelism is independent, so multiply by cores.

**Losing the fine grain of the width is a real cost.** A bit decomposition could prove 24 or 40 bits directly, which is what made the per-rail width optimisation of section 2.1 work. With only powers of two, securities at 24 bits round up to 32 and cash at 40 to 64. The conclusion here is that the table above is still a large enough difference to swallow that.

## 9. What is still missing

- The cash rail carries no tag, because hiding *which cash* means nothing with a single settlement currency. Making it multi-currency is the same construction applied once more, but it is neither built nor measured.
- Whoever sent a note can tell that it was spent, because they know the `g^S` they built. That is unavoidable in this construction. To a third party the ring size is the limit of what is learned.
- Collateral is handled as an already-valued amount. Turning pledged securities into a valuation --- quantity x price, against a price the quorum signed --- is not implemented, and a deployment where collateral and credit are different assets needs it.
- The Rust side has no note-rail DvP (`note_settlement`). The account rail, netting, credit and notes on their own are ported; the measurement in section 5.1 exists only in Python.
- Working a waterfall through to the ledger is not wired up. It proves and verifies; writing the tranches down is still the caller's job.
