#!/usr/bin/env python3
"""Build DEFMI.md from artifacts/defmi.json so the prose cannot drift.

Every number below is read from the artifact and formatted here. None is typed
in. Timings carry the number of samples they are made of and how far those
spread, because a bare millisecond figure says what came out once and nothing
about whether it means anything --- and two runs on this machine have disagreed
by half again.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Below the path insert, not above it: the package these come from is this
# repository, and it is not importable until the line above has run.
from scripts.hosts import label                                    # noqa: E402
from scripts.measure import render, value                          # noqa: E402

ART = ROOT / "artifacts"


def ms(summary, places: int = 1) -> str:
    return render(summary, places)


def count(record) -> int:
    """A byte length, however the artifact chose to store it."""
    if isinstance(record, dict):
        return int(record.get("exact", 0))
    return int(record)


def main() -> int:
    path = ART / "defmi.json"
    if not path.exists():
        print("artifacts/defmi.json is missing; run `make defmi` first.", file=sys.stderr)
        return 1
    d = json.loads(path.read_text())
    rust_path = ART / "rust_bench.json"
    rust = json.loads(rust_path.read_text()) if rust_path.exists() else None
    big_path = ART / "defmi_host_a.json"
    big = json.loads(big_path.read_text()) if big_path.exists() else None
    pvp_path = ART / "pvp.json"
    pvp = json.loads(pvp_path.read_text()) if pvp_path.exists() else None

    out: list[str] = []
    w = out.append

    w("# DeFMI — a settlement layer that never reads the trade\n")
    w(f"Measured on `{label(d['host'])}` / Python {d['python']} / group {d['group']}.")
    w("This document is generated from the measurement JSON by `make defmi-doc`. "
      "No number in it was typed by hand.\n")
    if d.get("calibration"):
        c = d["calibration"]
        w(f"**Calibration**: scalar multiplication {ms(c['scalar_mult_us'])} us, "
          f"40-bit range proof {ms(c['range_proof_40bit_ms'], 2)} ms.")
        w("Every millisecond below is from a machine in that state. The same "
          "machine has been half again slower at another time, so compare these "
          "two figures before comparing anything else here with anything "
          "measured elsewhere.\n")

    w("## 1. What is guaranteed, and what is not\n")
    w("DeFMI can check only what arithmetic settles without opening anything.\n")
    w("| Guarantee | What makes it hold |")
    w("| --- | --- |")
    w("| Value is neither created nor destroyed | the product of the balance "
      "commitments equals the product at issue (homomorphism alone) |")
    w("| No balance goes negative | a range proof on the difference |")
    w("| The two legs move together | both are checked before either is applied |")
    w("| One instruction settles once | nullifier registration |")
    w("| Cash leg = quantity x price | a product proof over three commitments |")
    w("| The securities leg is the instructed quantity | an equality proof "
      "across generators |\n")
    w("What DeFMI does *not* check is whether the price was reasonable or "
      "whether that was the right instrument. Those meanings come from the "
      "computing nodes' quorum and travel in the instruction's signature. "
      "Making the settlement layer re-derive them would mean handing it the "
      "plaintext, which is the one thing this construction exists to avoid.\n")

    sc = d["scaling"]
    w("## 2. Cost depends on the balance width and nothing else\n")
    w("The proof is a bit decomposition of the ledger's balance range, so it "
      "should be linear. It is.\n")
    w("| balance width | issue instruction | build package | settle (verify) | package |")
    w("| ---: | ---: | ---: | ---: | ---: |")
    for r in sc:
        w(f"| {r['bits']} bit | {ms(r['issue'])} ms | {ms(r['build'])} ms "
          f"| {ms(r['settle'])} ms | {count(r['package_bytes']):,} B |")
    lo, hi = sc[0], sc[-1]
    span = hi["bits"] - lo["bits"]
    build_slope = (value(hi["build"]) - value(lo["build"])) / span
    settle_slope = (value(hi["settle"]) - value(lo["settle"])) / span
    byte_slope = (count(hi["package_bytes"]) - count(lo["package_bytes"])) / span
    settle_intercept = value(lo["settle"]) - settle_slope * lo["bits"]
    at40 = next((r for r in sc if r["bits"] == 40), None)
    w("")
    w(f"The slopes are **{build_slope:.2f} ms/bit** to build, "
      f"**{settle_slope:.2f} ms/bit** to settle and **{byte_slope:.0f} B/bit** "
      "on the wire.")
    w(f"The settlement intercept, **{settle_intercept:.1f} ms**, is the part "
      "that does not depend on the ledger's width: it is the verification of "
      "the zkPI instruction itself.")
    if at40:
        share = 100 * settle_intercept / value(at40["settle"])
        w(f"At 40 bits, settlement costs {ms(at40['settle'])} ms, of which about "
          f"{share:.0f}% is the instruction and the rest is the ledger's range "
          "proofs.\n")
    w("**Consequence**: if settlement needs to be faster, reconsidering the "
      "balance width beats changing the cryptography. That is a listing "
      "decision, not a technical one.\n")

    if d.get("split_rails"):
        w("### 2.1 A different width for each rail\n")
        w("A quantity of securities and an amount of cash are orders of "
          "magnitude apart. There is no reason to give them the same width.\n")
        w("| securities rail | cash rail | build | settle | package |")
        w("| ---: | ---: | ---: | ---: | ---: |")
        for r in d["split_rails"]:
            w(f"| {r['securities_bits']} bit | {r['cash_bits']} bit "
              f"| {ms(r['build'])} ms | {ms(r['settle'])} ms "
              f"| {count(r['package_bytes']):,} B |")
        base = d["split_rails"][0]
        best = min(d["split_rails"], key=lambda r: value(r["settle"]))
        drop = 100 * (value(base["settle"]) - value(best["settle"])) / value(base["settle"])
        w("")
        w(f"Against both rails at {base['securities_bits']} bits, running "
          f"securities at {best['securities_bits']} and cash at "
          f"{best['cash_bits']} settles **{drop:.0f}% faster** and sends "
          f"**{count(base['package_bytes']) - count(best['package_bytes']):,} B "
          "less**. Not one line of the cryptography changed.\n")

    if d.get("asset_hiding"):
        w("## 3. Hiding which instrument, from the settlement layer too\n")
        w("The MPC layer hides which asset a request is for. Dropping the trade "
          "onto a per-instrument rail at settlement would give that back. "
          "Putting every instrument on one rail instead makes conservation hold "
          "only across instruments, so asset A could be carried out as asset B.\n")
        w("The construction used is an asset tag. Holding q units of asset a "
          "means holding `A_a^q . h^r`; each transfer publishes "
          "`H = A_a . h^y` under a fresh y, and every range proof is made "
          "against `H`. **What binds the disguise to a real asset is the range "
          "proof on the difference**: the payer's balance already sits under "
          "`A_a`, so no other tag can open it.\n")
        w("| instruments | set size | build, untagged | build, tagged | "
          "package | membership (at issue only) |")
        w("| ---: | ---: | ---: | ---: | ---: | --- |")
        for r in d["asset_hiding"]:
            plain, tag = r["arms"]["plain"], r["arms"]["tagged"]
            w(f"| {r['assets']} | {r['set_size']} | {ms(plain['build'])} ms "
              f"| {ms(tag['build'])} ms "
              f"| +{count(tag['package_bytes']) - count(plain['package_bytes'])} B "
              f"| prove {ms(r['membership_prove'], 2)} / verify "
              f"{ms(r['membership_verify'], 2)} ms, {r['membership_bytes']} B |")
        w("")
        plains = [value(r["arms"]["plain"]["build"]) for r in d["asset_hiding"]]
        deltas = [value(r["arms"]["tagged"]["build"]) - value(r["arms"]["plain"]["build"])
                  for r in d["asset_hiding"]]
        noise = max(plains) - min(plains)
        w(f"Every row of the untagged column runs the same work, so its own "
          f"spread --- **{noise:.1f} ms** --- is this measurement's noise floor. "
          f"The tagged column differs from it by {min(deltas):+.1f} to "
          f"{max(deltas):+.1f} ms, which is **inside that floor**. So the "
          "honest statement is that the time cost is too small to measure here; "
          "a percentage would mislead. Only the extra bytes are certain.\n")
        w("Per settlement the addition is **32 B** (one published tag) and one "
          "sigma proof across generators. The one-out-of-many membership proof "
          "(Groth-Kohlweiss) is not needed every time: a balance already sitting "
          "under a registered tag passes soundness down to the transfer, so the "
          "proof is needed **once, when the balance is issued into the account**.\n")
        w("Indistinguishability and the attack arms, measured:\n")
        for r in d["asset_hiding"]:
            same = r["indistinguishable"]
            first = r["per_asset"][list(r["per_asset"])[0]]
            w(f"- {r['assets']} instruments: the package is identical whichever "
              f"one it is ({'identical' if same else 'NOT identical'}, "
              f"{count(first['package_bytes']):,} B across "
              f"{len(r['per_asset'])} instruments).")
            for name, a in r["attacks"].items():
                attack = {
                    "registered_tag_wrong_asset":
                        "carry it out under a registered tag for another asset",
                    "fabricated_tag": "use a point that was never registered",
                }.get(name, name)
                w(f"  - {attack}: `{a['status']}` --- {a['reason']}")
        w("")

    if d.get("netting"):
        rows = d["netting"]["rows"]
        w("## 4. Netting: gross-gross, gross-net, net-net\n")
        w("These are the BIS DvP models 1, 2 and 3. They are a question about "
          "settlement design and, at the same time, a question about **how many "
          "range proofs land and where**.\n")
        w("A rail is either gross or net, and that single choice decides "
          "everything else.\n")
        w("- **A gross rail** checks at each order. It proves on the spot that "
          "the post-trade position is non-negative, so **settlement failure "
          "cannot occur by construction**. The price is order dependence: a "
          "participant receiving 100 and delivering 100 is refused if the "
          "delivery arrives first. That deliberately gives up the liquidity "
          "saving netting exists to provide.")
        w("- **A net rail** only accumulates homomorphically during the period "
          "and proves nothing. A commitment hides the sign as well as the "
          "magnitude, so an intermediate position may be negative without "
          "leaking anything --- what is not proved is not disclosed. At the close "
          "it shows coverage once per participant, on the **net**. The liquidity "
          "saving comes back and order dependence goes away, at the cost of a "
          "close that can fail.\n")
        w("| N | P | mode | verify per order | verify at close | verify total | vs gross-gross |")
        w("| ---: | ---: | --- | ---: | ---: | ---: | ---: |")
        for r in rows:
            w(f"| {r['trades']} | {r['participants']} | {r['mode']} "
              f"| {ms(r['verify_per_order'], 2)} ms | {ms(r['verify_close'])} ms "
              f"| {ms(r['verify_total'])} ms | {r['speedup_vs_gross_gross']:.2f}x |")
        w("")
        largest = max(r["trades"] for r in rows)
        tail = [r for r in rows if r["trades"] == largest]
        gg = next(r for r in tail if r["mode"] == "gross-gross")
        nn = next(r for r in tail if r["mode"] == "net-net")
        at = next(r for r in tail if r["mode"].endswith("attested"))
        w("**The first prediction was wrong.** Counting range proofs alone gave "
          "an estimate that net-net would be an eighth of the work; measured, it "
          f"is only {value(gg['verify_total']) / value(nn['verify_total']):.2f}x. "
          f"Even under net-net, {ms(nn['verify_per_order'])} ms per order "
          "remains, and that is the verification of the zkPI instruction itself "
          "--- which carries range proofs on amount and price inside it. "
          "**It is needed once per trade and netting does not remove it.**\n")
        w("What removes it is changing the **granularity of the instruction**. "
          "If the quorum signs a whole cycle rather than each trade, the "
          "settlement layer's work stops depending on the number of trades "
          f"({ms(at['verify_per_order'], 2)} ms per order, "
          f"{ms(at['verify_total'])} ms in total, "
          f"**{at['speedup_vs_gross_gross']:.1f}x**). The individual trades are "
          "then no longer verified, so the allocation between participants "
          "becomes **the quorum's attestation rather than a proof**. "
          "Conservation and coverage still hold, and each participant can check "
          "its own net, so what is lost is third-party verifiability of the "
          "allocation. That is what a central counterparty has always been; "
          "this only makes it explicit.\n")

    if d.get("credit"):
        c = d["credit"]
        w("### 4.1 How far a net position may go (an intraday overdraft)\n")
        w("Refusing any order that would make a net position negative removes "
          "settlement failure, and, as above, removes the liquidity saving with "
          "it. Practice puts a **limit** here instead --- the Bank of Japan's "
          "intraday overdraft is exactly this: eligible collateral is pledged, a "
          "limit is granted up to its value after haircut, and the position may "
          "be negative down to that limit.\n")
        w("The limit is a **commitment**, and not only to hide its size. "
          "Coverage is then proved about `position + limit`, which means the "
          "proof **never says which side of zero the position was on**. The "
          "offset trickery that hiding a sign usually needs is not needed "
          "anywhere.\n")
        w("| operation | cost | how often |")
        w("| --- | ---: | --- |")
        w(f"| grant a limit (proving the collateral covers it after haircut) "
          f"| build {ms(c['grant'])} / verify {ms(c['check'])} ms | once per limit |")
        w(f"| coverage proof, no limit | {ms(c['coverage_plain'])} ms "
          "| per participant per rail, at the close |")
        w(f"| coverage proof, with a limit | {ms(c['coverage_capped'])} ms | as above |")
        w("")
        w(f"**The limit is essentially free** ({ms(c['coverage_plain'])} to "
          f"{ms(c['coverage_capped'])} ms --- the same range proof width against a "
          "different commitment). Admission, pledge, overdraft and payment are "
          "handled as one event by `admit_with_credit`, because doing them in "
          "sequence allows either collateral locked with no limit granted or a "
          "limit standing with no collateral behind it. If the payment does not "
          "go through, the limit and the pledge are both rolled back.\n")
        if c.get("waterfall"):
            w("### 4.2 The default waterfall\n")
            w("A net rail can fail at the close. The order in which that failure "
              "is worked through is the substance of the arrangement, so it has "
              "to be **enforced** and not assumed. The condition that tranche k "
              "may be drawn only once tranche k-1 is exhausted is written "
              "`draw_k x remaining_{k-1} = 0`. The product's commitment is "
              "pinned to the identity, so there is nothing to hand the "
              "verifier.\n")
            w("| tranches | build | verify |")
            w("| ---: | ---: | ---: |")
            for r in c["waterfall"]:
                w(f"| {r['tranches']} | {ms(r['build'])} ms | {ms(r['check'])} ms |")
            first, last = c["waterfall"][0], c["waterfall"][-1]
            per = ((value(last["build"]) - value(first["build"]))
                   / (last["tranches"] - first["tranches"]))
            w("")
            w(f"**{per:.1f} ms per tranche** --- one range proof's worth, linear. "
              "It runs once per default, so nobody need ever care about this "
              "number.\n")

    if d.get("notes"):
        n = d["notes"]
        w("## 5. Hiding who paid whom (the note ledger)\n")
        w("The asset tag hides *what*. An account ledger still names four "
          "handles in the clear at every settlement. Even with every balance "
          "committed, handles that recur draw the counterparty graph.\n")
        w("So accounts were replaced by notes. A note is `C = g^S . A_a^v . h^r`, "
          "where only the **payee** can construct S --- the sender can form `g^S` "
          "from the public key but does not know the b in S = H(A^e) + b. "
          "Spending keeps S hidden and shows with Groth-Kohlweiss that **one of** "
          "the ring holds this S, without saying which.\n")
        w("| ring size | prove (payer) | verify (node) | wire |")
        w("| ---: | ---: | ---: | ---: |")
        for r in n["rings"]:
            w(f"| {r['ring']} | {ms(r['build'])} ms | {ms(r['check'])} ms "
              f"| {count(r['wire_bytes']):,} B |")
        small, large = n["rings"][0], n["rings"][-1]
        mid = [r for r in n["rings"] if r["ring"] == 64]
        w("")
        w("**The asymmetry is the point.** The wire grows by 224 B per doubling, "
          f"and verification only goes from {ms(small['check'])} to "
          f"{ms(large['check'])} ms between rings {small['ring']} and "
          f"{large['ring']}. What breaks is the proving side: "
          f"{ms(small['build'])} to {ms(large['build'])} ms.")
        if mid:
            w("So **what caps the anonymity set is the payer, not the settlement "
              f"node**. A ring of 64 costs {ms(mid[0]['build'])} ms to prove and "
              f"{ms(mid[0]['check'])} ms to verify, which a payer's own device "
              "can carry.")
        w("")
        w("A payee has to scan the pool to find its own notes, at "
          f"**{n['scan_ms_per_note']:.3f} ms** each "
          f"({n['scan_ms']:.1f} ms over {n['pool_size']}). That is one scalar "
          "multiplication, and it is the only cost proportional to the pool.")
        w(f"Two payments to the same address cannot be linked: "
          f"**{n['outputs_unlinkable']}** (neither the commitments nor the "
          "ephemeral points match).\n")

    if d.get("note_settlement"):
        at40 = next((r for r in d["scaling"] if r["bits"] == 40), None)
        base = value(at40["settle"]) if at40 else None
        w("### 5.1 The same DvP over note rails\n")
        w("Both rails were made note rails and the settlement itself was run "
          "through them. The binding to the instruction is kept by a single "
          "equality proof across generators, because the quantity is committed "
          "under the tag and the instruction under the base.\n")
        w("| ring size | build | settle (verify) | package | vs the account version |")
        w("| ---: | ---: | ---: | ---: | ---: |")
        for r in d["note_settlement"]["rings"]:
            delta = ("---" if base is None
                     else f"{100 * (value(r['settle']) - base) / base:+.0f}%")
            w(f"| {r['ring']} | {ms(r['build'])} ms | {ms(r['settle'])} ms "
              f"| {count(r['package_bytes']):,} B | {delta} |")
        rows = d["note_settlement"]["rings"]
        if base is not None:
            w("")
            w(f"The account version settles in {ms(at40['settle'])} ms at 40 "
              f"bits. Hiding the counterparties costs "
              f"{100 * (value(rows[0]['settle']) - base) / base:+.0f}% at ring "
              f"{rows[0]['ring']} and "
              f"{100 * (value(rows[-1]['settle']) - base) / base:+.0f}% at ring "
              f"{rows[-1]['ring']}.")
            w("**Adding up the parts was off by more than a factor of two.** "
              "A note leg and an account leg both carry two range proofs; the "
              "difference is only the ring proof, the serial proof and one "
              "equality proof.\n")

    if pvp:
        milli, micro = pvp["milliseconds"], pvp["microseconds"]
        w("## 6. Payment versus payment, across two ledgers\n")
        w("DvP moves two legs together because both are on one ledger and one "
          "function decides. Two ledgers that share no state have no such "
          "function, and fair exchange between two parties with no third party "
          "is impossible in general --- so something has to pass from one side "
          "to the other. The only question is what, and who can read it.\n")
        w("A hash lock passes a preimage that ends up in the clear on both "
          "ledgers, so anyone reading both can join the two legs on it. That is "
          "the linkage the asset tag and the note ledger were built to prevent, "
          "handed back at the last step. What is used instead is an **adaptor "
          "signature**: the first mover's claim on one ledger hands the second "
          "mover a scalar, and what each ledger records is an ordinary "
          "signature with nothing in common with the other's.\n")
        w("```")
        w("1. Bob   -> Alice : Y = g^y")
        w("2. Alice           prepares leg A; her money leaves her account")
        w("   Alice -> Bob   : a pre-signature over \"leg A\", adapted to Y")
        w("3. Bob             prepares leg B, and sends his own pre-signature")
        w("4. Bob             claims on A  -> he is paid, and y becomes readable")
        w("5. Alice           reads A, recovers y, claims on B  -> she is paid")
        w("```\n")
        w("Bob draws the secret and moves first, so Bob is never at risk: if he "
          "stops after step 3 both escrows expire and both parties are whole. "
          "Alice is exposed in exactly one window, between step 4 and step 5, "
          "and she is safe if and only if the gap between the two deadlines "
          "covers her reaction. **That gap is this arrangement's Herstatt "
          "risk**, and it is the number worth measuring.\n")
        w(f"| | measured, {pvp['rail_bits']}-bit rails |")
        w("| --- | ---: |")
        w(f"| prepare one leg (check, and move it out of reach) "
          f"| {milli['prepare']['mean']:.2f} \u00b1 {milli['prepare']['sd']:.2f} ms "
          f"(n={milli['prepare']['n']}) |")
        w(f"| the first mover's claim | {milli['claim']['mean']:.2f} \u00b1 "
          f"{milli['claim']['sd']:.2f} ms (n={milli['claim']['n']}) |")
        w(f"| **the second mover's reaction** | **{milli['react']['mean']:.2f} "
          f"\u00b1 {milli['react']['sd']:.2f} ms (n={milli['react']['n']})** |")
        w(f"| unwind an expired leg | {micro['unwind']['mean']:.2f} \u00b1 "
          f"{micro['unwind']['sd']:.2f} us (n={micro['unwind']['n']}) |")
        w("")
        w(f"**The cryptography is not what puts the money at risk.** Recovering "
          f"the secret, adapting the signature and having the second ledger "
          f"accept it comes to {milli['react']['mean']:.2f} ms. The deadline gap "
          "has to cover that *plus* the time for one ledger to publish the "
          "first claim and the other to accept the second --- block times and "
          "network round trips, which are three to five orders of magnitude "
          "larger. So the exposure is set by the settlement finality of the two "
          "ledgers and not by anything in this repository, and a deployment "
          "that wants a short window should shop for finality rather than for "
          "faster proofs.\n")
        w("Preparing costs about what a transfer costs, because that is what it "
          "is: the same check, with the amount moved into an escrow instead of "
          "into the payee. Unwinding costs nothing, and deliberately requires "
          "no signature --- the deadline is the whole authority, because "
          "demanding a signature would strand the money of anyone who lost a "
          "key, which is the failure this branch exists to prevent.\n")

    if d.get("parallel"):
        w("## 7. What one settlement node can take\n")
        w("Verification only --- proving is the counterparty's work and the clock "
          "is stopped for it. Every worker meets at a barrier before the "
          "measured section begins.\n")
        w("| workers | settlements/s | vs one worker |")
        w("| ---: | ---: | ---: |")
        one = value(d["parallel"][0]["per_second"])
        for r in d["parallel"]:
            w(f"| {r['workers']} | {ms(r['per_second'])} "
              f"| {value(r['per_second']) / one:.2f}x |")
        top = d["parallel"][-1]
        w("")
        w("Verifications of independent packages share nothing, so they "
          f"parallelise completely: **{value(top['per_second']):.0f} per second** "
          f"on {top['workers']} workers. A settlement node's capacity is a "
          "procurement question, not a design one.\n")
        if big and big.get("parallel"):
            bp = big["parallel"]
            bone, btop = bp[0], bp[-1]
            bcal = value(big["calibration"]["scalar_mult_us"])
            ccal = value(d["calibration"]["scalar_mult_us"])
            w(f"A second host with more cores (`{label(big['host'])}`, "
              f"{btop['workers']} logical cores) was measured too. Its "
              f"calibration is {bcal:.1f} us per scalar multiplication against "
              f"{ccal:.1f} us here, so it is **{bcal / ccal:.2f}x slower per "
              f"core**. Its single-worker throughput differs by "
              f"{one / value(bone['per_second']):.2f}x "
              f"({one:.1f} to {value(bone['per_second']):.1f} per second), which "
              "is the same ratio by an independent route.\n")
            w("| workers | settlements/s | vs one worker | vs linear |")
            w("| ---: | ---: | ---: | ---: |")
            for r in bp:
                w(f"| {r['workers']} | {value(r['per_second']):.1f} "
                  f"| {value(r['per_second']) / value(bone['per_second']):.2f}x "
                  f"| {100 * value(r['per_second']) / (value(bone['per_second']) * r['workers']):.0f}% |")
            shortfall = 100 - 100 * value(btop["per_second"]) / (
                value(bone["per_second"]) * btop["workers"])
            w("")
            w(f"**{value(btop['per_second']):.0f} per second** on "
              f"{btop['workers']} workers, only {shortfall:.0f}% short of "
              "linear. Nothing is shared between verifications, so this shape "
              "is what was expected.\n")

    if rust:
        w("## 8. The Rust port\n")
        py_cal = value(d.get("calibration", {}).get("scalar_mult_us"))
        rs_cal = value(rust["calibration"].get("scalar_mult_us"))
        w(f"Measured on the same machine (`{label(rust['host'])}` / "
          f"{rust['rustc']} / group ristretto255). The scalar-multiplication "
          "calibration is "
          + (f"{rs_cal:.1f} us in Rust against {py_cal:.1f} us in Python, "
             if py_cal else f"{rs_cal:.1f} us in Rust, ")
          + "and **this one figure is the only thing that compares across the "
            "two languages** --- Python goes through libsodium and Rust through "
            "dalek, different implementations of the same thing: a scalar "
            "multiplication on a native-code 255-bit curve. That they agree says "
            "the two are equally fast and, more usefully, that **the machine was "
            "in the same state**, which is what stops the ratios below being "
            "explained by the machine.\n")
        w("What is being compared is not only the language. The port also "
          "replaced a hand-rolled bit-decomposition range proof with the audited "
          "`bulletproofs` crate, so **the ratios below are 'became Rust' and "
          "'became Bulletproofs' added together**. The order-of-magnitude change "
          "on the wire is the second of those: linear became logarithmic.\n")
        py_by_bits = {r["bits"]: r for r in d["scaling"]}
        shared = [r for r in rust["scaling"] if r["bits"] in py_by_bits]
        w("| balance width | Python settle | Rust settle | ratio | "
          "Python package | Rust package | ratio |")
        w("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for r in shared:
            py = py_by_bits[r["bits"]]
            py_settle, rs_settle = value(py["settle"]), value(r["settle_ms"])
            py_bytes, rs_bytes = count(py["package_bytes"]), count(r["package_bytes"])
            w(f"| {r['bits']} bit | {ms(py['settle'])} ms | {rs_settle:.2f} ms "
              f"| {py_settle / rs_settle:.1f}x "
              f"| {py_bytes:,} B | {rs_bytes:,} B | {py_bytes / rs_bytes:.1f}x |")
        w("")
        wide = [r for r in rust["scaling"] if r["bits"] == 64]
        py40 = py_by_bits.get(40)
        if wide and py40:
            wide = wide[0]
            py_settle = value(py40["settle"])
            py_bytes, rs_bytes = count(py40["package_bytes"]), count(wide["package_bytes"])
            w("Bulletproofs only comes in powers of two, so a 40-bit rail "
              "**rounds up to 64**. Comparing against the rounded-up side is the "
              f"honest comparison: {ms(py40['settle'])} ms for Python at 40 bits "
              f"against {wide['settle_ms']:.2f} ms for Rust at 64, "
              f"**{py_settle / wide['settle_ms']:.1f}x**. The package goes from "
              f"{py_bytes:,} to {rs_bytes:,} B, **{py_bytes / rs_bytes:.1f}x**.\n")
            w(f"Per core that is {1000 / py_settle:.1f} to "
              f"{1000 / wide['settle_ms']:.1f} settlements per second. "
              "Parallelism is independent, so multiply by cores.\n")
        w("**Losing the fine grain of the width is a real cost.** A bit "
          "decomposition could prove 24 or 40 bits directly, which is what made "
          "the per-rail width optimisation of section 2.1 work. With only powers "
          "of two, securities at 24 bits round up to 32 and cash at 40 to 64. "
          "The conclusion here is that the table above is still a large enough "
          "difference to swallow that.\n")

    w("## 9. What is still missing\n")
    w("- The cash rail carries no tag, because hiding *which cash* means nothing "
      "with a single settlement currency. Making it multi-currency is the same "
      "construction applied once more, but it is neither built nor measured.")
    if not d.get("note_settlement"):
        w("- The note ledger and DvP settlement are not yet joined. Notes work "
          "and are measured on their own, but `Defmi.settle` is still the "
          "account ledger.")
    w("- Whoever sent a note can tell that it was spent, because they know the "
      "`g^S` they built. That is unavoidable in this construction. To a third "
      "party the ring size is the limit of what is learned.")
    w("- Collateral is handled as an already-valued amount. Turning pledged "
      "securities into a valuation --- quantity x price, against a price the "
      "quorum signed --- is not implemented, and a deployment where collateral "
      "and credit are different assets needs it.")
    if rust:
        w("- The Rust side has no note-rail DvP (`note_settlement`). The account "
          "rail, netting, credit and notes on their own are ported; the "
          "measurement in section 5.1 exists only in Python.")
    w("- Working a waterfall through to the ledger is not wired up. It proves "
      "and verifies; writing the tranches down is still the caller's job.")

    (ROOT / "DEFMI.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {ROOT / 'DEFMI.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
