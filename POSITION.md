# What is new here, and what is not

Every mechanism in this stack has a paper behind it, and for most of them the
paper is older than the stack. That is not a problem to be hidden; it is the
thing to be precise about, because a reviewer will find it in an afternoon and
the only question is whether we found it first.

This document is that precision. It states the claim, states the three claims it
is *not*, and then goes line by line against the three nearest pieces of prior
work: the paper that invented the audit mechanism (2014), the paper that most
recently improved it (2026), and the system that most closely does this job in
production (2023). It ends with the settlement leg, which is where the
difference stops being about MPC at all.

**The position is an applied one.** This is not a protocol paper. Nothing below
claims a new primitive, a new security proof, or a better asymptotic. What it
claims is a composition, a set of measurements of that composition on real
market data, and a small number of findings that only appear when you build it.

---

## 1. The claim, and the three it is not

> **Claim.** A request-for-quote market can be run so that no participant --- the
> venue included --- learns a maker's pricing policy or the losing quotes, while
> anyone can verify afterwards that the quote returned was the best of those
> submitted and that the trade settled at that price. This document's
> contribution is the composition and the measured cost of every link in it,
> including the ones that turned out to be unaffordable.

Three things that are **not** claimed, each of which was claimed in an earlier
draft of this repository and is now retracted:

**Not: that this makes MPC publicly auditable.** That is Baum, Damg{\aa}rd and
Orlandi, SCN 2014. Section 2.

**Not: that VOLE-in-the-Head commitments are a new way to get post-quantum
auditable MPC.** That is Baum and Zok, `eprint 2026/337`, February 2026.
Section 3.

**Not: that this is the first secure computation deployed in finance.** That is
Prime Match, in production at J.P. Morgan since 2023. Section 4.

---

## 2. Against publicly auditable MPC (Baum, Damg{\aa}rd, Orlandi, SCN 2014)

**Theirs.** Input providers publish Pedersen commitments to their inputs. The
online phase of SPDZ consists entirely of openings of linear secret sharings, so
if every protocol message goes to a bulletin board, an auditor can replay the
same linear operations on the *commitments* and confirm the output. Privacy
holds if one party is honest; **correctness holds even if every party is
corrupt**, which is the point and is stronger than what MPC alone gives.

**That is the construction `quote_proof.py` instantiates.** Not a variant of it,
not an independent rediscovery of it --- it is the same idea, and the repository
now says so in the first section of `BINDING.md` rather than in a footnote.

Six things differ, and only two of them are about cryptography.

### 2.1 The corruption model is the other one

They are dishonest majority (SPDZ, `n-1` corruptions). This is **honest majority
--- Shamir over seven nodes, `T = 2`, malicious**. That is a weaker assumption
about the world and it buys an information-theoretic online phase with no MACs
at all, which changes what the audit has to attach to. It also means the audit
covers a case they do not have to consider and they cover a case this does not:
their correctness survives all seven nodes colluding, and this stack's does too
for the quote proof, but its *privacy* does not survive three.

### 2.2 The input parties are not the computing parties

A market maker deals its policy to seven nodes and is not one of them. In the
2014 blueprint --- and, explicitly, in the 2026 successor --- the input providers
*are* the computing parties. That separation is what creates the gap this whole
repository is about: `qomm_transport/roles.py` can prove a node received a
committed share, and cannot prove the node fed that share to MP-SPDZ.

Baldimtsi et al. do separate them, and also consider corrupt input parties. This
stack does not have their construction; it has the gap, named, and two priced
ways of closing it.

### 2.3 The field problem is theirs too, and here it is a number

Their construction "can only be instantiated for computations over fields as
large as Discrete Logarithm-hard groups" --- their own successor's phrasing. That
is section 1 of `BINDING.md`, written independently and then found in the
literature, which is the right order but not the flattering one.

What is here that is not there: **what it costs.** MP-SPDZ, seven parties,
malicious honest-majority Shamir, the quote circuit, compiled to the 253-bit
group order instead of its native 128-bit prime:

| | ratio |
|---|---:|
| rounds | **1.00x** |
| traffic | **2.00x** --- the element width, 16 bytes to 32, and nothing else |
| wall clock at 15 ms RTT | 1.07x |
| wall clock at 120 ms RTT | 1.06x |

**Matching the field is affordable**, and the conclusion in `BINDING.md` section
4 turns on that measurement. It is cheaper cross-region than in a datacentre,
because the round count does not move and the round trips are what dominate
there. Nothing in the 2014 paper says whether this is 1.07x or 14x; it is not
that kind of paper.

### 2.4 The audited statement is a market statement

Their auditor checks that the output is the correct evaluation of the circuit.
Here the circuit is a market mechanism, and `quote_proof.py` proves the
statement that means something to a regulator rather than the one that means
something to a cryptographer:

> for each maker `i`, `key_i` is the committed policy applied to the committed
> request, and the opened winner is the smallest of those keys

Minimality plus membership is exactly best execution. Measured: 152 ms to prove
and 173 ms to verify at four makers, 307 and 350 at eight, `host-a`. That the
statement is *about best execution* rather than *about circuit correctness* is a
choice in how the circuit and the proof are cut, and it is the choice that makes
the artifact usable by somebody who does not read this document.

### 2.5 The output has to settle, and their story ends at the output

Section 5.

### 2.6 What is published is deliberately noised

The quote that comes out is disclosed under a differential-privacy budget rather
than in the clear, because a venue that publishes exact winning quotes leaks the
policy through repetition. Nothing in the auditable-MPC line addresses what the
*output itself* reveals; it addresses whether the output is right. **These are
orthogonal and both are needed**, and combining them creates a problem neither
has alone: the audited value and the published value are not the same value, so
the audit has to be of the pre-noise quantity and the noise has to be provably
drawn. The second half of that is not finished --- see section 6.

---

## 3. Against `eprint 2026/337` (Baum and Zok, February 2026)

The nearest work, six months old, and it does deliberately what section 4.6 of
`BINDING.md` set out to try: replace the Pedersen commitments in the 2014
blueprint with publicly verifiable commitments from VOLE-in-the-Head, so that
public auditability rests on a random oracle and nothing else. UC-secure,
post-quantum, OLE-based preprocessing instead of lattice SHE.

**So the cryptographic idea is taken, and this repository should not claim it.**
What remains is a division of labour that is real rather than consoling:

| | 2026/337 | here |
|---|---|---|
| VOLEitH commitments for auditable MPC | **the contribution** | not claimed |
| security proof | UC, 68 pages | none |
| corruption | dishonest majority, all-corrupt audit | honest majority, `T=2` of 7 |
| input vs computing parties | **not separated** (stated in the paper) | separated; that is the gap |
| binary circuits | open problem (their appendix A) | not needed |
| implementation | **none** | `zk/voleith.py` |
| efficiency | asymptotic estimate, `O(n*lambda^2*|C|)` online | measured |

**They report no benchmarks.** Their appendix C is an estimate --- "we estimate
the communication complexity" --- with 5 offline rounds and `4 + D` online, and
an online term of `O(n*lambda^2*|C|)` bits which they note could "trivially be
lowered" to `O(n*lambda*log(lambda)*|C|)` with GGM trees, without doing it.

What is here, measured on `host-a` at n=30 over 167 committed values, both arms
proving the same public linear statement and both publicly verifiable:

| | prove | verify | proof |
|---|---:|---:|---:|
| Pedersen (ed25519) | 18.64 ms | 15.48 ms | 5,440 B |
| VOLE-in-the-Head | 73.06 ms | 69.94 ms | 45,616 B |

and the finding that only shows up once it exists: **88% of that proof is the
VOLE consistency corrections**, `repeats - 1` vectors of `n` field elements,
and the all-but-one tree openings are 4%. Over `F_2` --- FAEST's setting, and
the setting of every published number for this construction --- those
corrections are bits. Over a 127-bit prime they are 16-byte elements. **The
published "2x the designated-verifier communication" does not carry over to a
witness that is not bits**, and neither does the computation: 17.8 MB of PRG
output against FAEST's 819 kB at identical tree parameters.

That is not a refutation of their paper --- their asymptotic has the `lambda^2`
in it, and this is what `lambda^2` looks like at `lambda = 128` with a wide
field. It is the number their paper does not contain, obtained by building the
commitment scheme and running it.

**And one property of theirs turned out to matter more than it reads.** Their
commitments are *one-time* linearly homomorphic: `Delta` is public after the
first opening, so a second statement about the same commitment is bound by
nothing. They buy a second opening with a random-oracle commitment to the
opening. In this stack a maker's policy commitment is opened against **every
quote for the life of the policy**, so the one-time property is not a technical
footnote --- it is a redesign of how policies are committed.
`voleith.Prover.prove` raises rather than allowing the second proof.

---

## 4. Against Prime Match (Polychroniadou et al., USENIX Security 2023)

The closest thing to this that actually runs. In production at J.P. Morgan, and
by their own description the first secure multiparty computation running live in
traditional finance. The motivation is nearly identical to this repository's:
clients must hand the bank their direction and size, and if that leaks the price
moves against them before they trade.

Four differences, and the first one is the one that matters.

### 4.1 There is a semi-honest party, and here there is not

Prime Match is secure against **malicious clients and a semi-honest bank**. The
bank is the hub of a star topology --- clients do not talk to each other, by
design, because they do not want to reveal their identities to each other --- and
it is trusted not to deviate.

That is a defensible engineering choice for a bank matching its own clients. It
is not available to a venue whose premise is that the venue cannot be trusted
with the order flow. **Here there is no semi-honest party**: seven nodes, up to
two malicious, and the venue is one of the seven or none of them.

### 4.2 The computation is a different size

Theirs is a two-party minimum between two quantities, invoked `n^2` times. Ours
is a seven-party tournament over `M` makers' committed pricing policies with
range checks, freshness checks and an inventory carry.

**Their throughput is about 10 symbols per second and they run every 30
minutes in production.** A quote here is 3.621 s at 15 ms RTT --- 3.877 s if the
field is matched to the group order --- and 23.0 s intercontinental, at
`M = 16` makers over four assets.

**The units are not the same unit and the ratio should not be reduced to one
number.** A Prime Match symbol is one two-party minimum; a quote here is a
seven-party tournament with proofs attached. What survives the difference is the
direction, and the direction is that **nothing here is faster than Prime
Match**, on any reading of the units. That should be said before anything else
in this section.

### 4.3 The outcome is not auditable by a third party

Nothing in Prime Match produces an object that a regulator who was not present
can check. Privacy is the goal and it is achieved; *provable* best execution is
not attempted. That is the axis this repository is on, and it is the reason the
comparison is not simply "they are faster".

### 4.4 What they have that should be read next

Their main cryptographic contribution is a **two-round secure linear comparison
protocol with no preprocessing and malicious security**. The tournament here is
comparisons, and the comparison is what the field-width argument in `BINDING.md`
is entirely about. Whether their construction transfers from two parties to
seven-party Shamir is not obvious and is not answered here.

---

## 5. The settlement leg, which none of the three has

Publicly auditable MPC ends when the output is opened. **A quote that is opened
and then settled in the clear has leaked everything the computation
protected**: the asset, the size, the counterparties and, by difference, the
policy. The audit trail is intact and the privacy is gone.

So the stack does not end at the output.

### 5.1 zkPI: the instruction is a commitment

`zk/zkpi.py` makes the payment instruction itself a commitment plus a proof. A
settlement venue checks that an instruction is well-formed, authorised and
unspent, and learns none of: the asset, the amount, the price, or which enrolled
entity holds it. What it learns is that *some* enrolled entity holds an
instruction whose asset and amount lie in declared ranges, whose price matches
the quote the computing nodes' quorum signed, whose deadline has not passed, and
whose nullifier is unseen.

### 5.2 DeFMI: the ledger checks arithmetic and nothing else

`DEFMI.md` is the settlement side. Homomorphic balances, so value is neither
created nor destroyed by the group operation alone; a range proof so no balance
goes negative; a product proof for cash = quantity x price; an equality proof
across generators so the securities leg is the instructed quantity; a nullifier
so an instruction settles once. Measured: **48.8 ms to settle at a 40-bit
balance width, 29,523 bytes on the wire**, of which about 53% is the instruction
and the rest the ledger's range proofs. Cost is linear in the balance width and
in nothing else --- 0.55 ms and 448 bytes per bit.

### 5.3 What is standard here and what is not

**Standard:** every gadget. Pedersen commitments, Bulletproofs range proofs,
Groth--Kohlweiss one-of-many for anonymous membership, nullifiers as in Zcash,
FROST for the quorum key, confidential-transaction balance arithmetic. Each has
a paper and none of those papers is this one.

**Not standard:** that the settlement leg is bound to the audited computation.
The price commitment that the quote proof shows is minimal is *the same
commitment* the quorum signs, is *the same commitment* the instruction carries,
and is *the same commitment* the ledger's product proof consumes. One value,
four proofs, never opened. **That chain is the composition being claimed**, and
it is why "the individual gadgets are standard" is an accurate statement rather
than a damaging one.

The nearest published thing is delivery-versus-payment on DLT, which assumes the
price is public. Prime Match does not settle at all --- a match is handed back to
the bank's existing trade pipeline.

---

## 6. The table

| | 2014 | 2026/337 | Prime Match | here |
|---|---|---|---|---|
| public audit of the outcome | **yes** | yes | no | yes |
| post-quantum | no | **yes** | no | no |
| security proof | yes | **UC** | yes | **none** |
| implemented | partly | **no** | **production** | prototype |
| measured on real market data | no | no | production | **yes** |
| corruption | dishonest maj. | dishonest maj. | semi-honest hub | honest maj. `T=2/7` |
| input != computing parties | no | **no** | yes | yes |
| private settlement | no | no | no | **yes** |
| disclosure budget on the output | no | no | no | **yes** |

**Read the columns, not the row totals.** Three of the four are papers with
proofs and this is a repository with measurements; the last three rows are where
it has something the others do not, and the "security proof: none" row is why
none of this is a cryptography result.

---

## 7. What is not finished

Stated here rather than left for a reader to find, because a position document
that lists only the strengths is an argument rather than a position.

- **No formal threat model.** Section 6's last row is not a rhetorical
  concession. There is no theorem here.
- **The differential-privacy noise is generated outside the MPC**, so the
  published quote is noised but not *provably* noised. That is the second half
  of section 2.6 and it is open.
- **Selective disclosure is unimplemented.** The design says which fields a
  supervisor can open; the code does not do it.
- **There has never been a seven-site deployment.** Cross-region figures come
  from a delay proxy on one machine, which reproduces round trips and not
  jitter, loss or clock skew.
- **The staleness measurement has selection bias.** It is UniswapX fills, which
  are the trades that happened, and the ones that did not are the interesting
  ones.
- **The VOLE-in-the-Head arm is one linear statement**, not the MPC protocol of
  `2026/337`, and the linear-code instantiation that would shrink its proof
  fourfold is arithmetic in `run_voleith.py` rather than code.

**And two papers that may be nearer than the three compared above have not been
read.** Both were found through `2026/337`'s related work rather than through a
search of our own, which is the second time in this project that the literature
turned up something structural after the design was fixed.

- **Baldimtsi, Kiayias, Zacharias and Zhang (ASIACRYPT 2020)** is, on the
  reading available, the one line of work that separates input parties from
  computation parties *and* considers corrupt input parties. **That is this
  stack's structure.** Section 2.2 is a difference from 2014 and may not be a
  difference from them. Reported to need super-polynomial assumptions and to
  cover only some functions, which is why it may still not apply --- but that is
  a claim about a paper nobody here has opened.
- **Rivinius, Reisert, Rausch and K{\"u}sters (IEEE S&P 2022)** extends the 2014
  blueprint with lattice commitments and, alone in the line, **lower corruption
  thresholds for robustness** --- the honest-majority direction this stack is
  already in at `T = 2` of 7.

Until those are read, the comparisons in sections 2 to 4 are against the nearest
work *that was read*, which is not the same claim as the nearest work.

---

## 8. What would make this a cryptography paper

One question, and it is not any of the above.

The tournament is comparisons; comparisons over a prime field need either bit
decomposition or slack; slack forces the field wider; a wider field costs
traffic on every quote forever. Rabbit (FC 2021) removes the slack by exploiting
the commutativity of addition over rings, and Prime Match gets a two-round
malicious comparison with no preprocessing at all. **Neither is stated for
seven-party Shamir with a commitment scheme that has to agree with the field.**

A construction that keeps the commitment field and the MPC field the same
*without* the round count or the proof size exploding in the way section 4.6
measured would be a result. Everything else in this repository is engineering
and measurement, which is what it is for.
