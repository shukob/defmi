#!/usr/bin/env python3
"""What agreeing with the book of record costs, and what looking for a break costs.

Two numbers matter and they are different in kind. Reconciling is cheap and
discloses nothing: one product and one sigma proof, whatever the ledger holds.
Finding *where* a reconciliation failed is the opposite --- it is the only
operation in DeFMI that discloses on purpose, and what it discloses is
subtotals, the narrowest of which is one balance.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from defmi.assets import asset_tag                                   # noqa: E402
from defmi.reconcile import (Attestation, check, check_positions,    # noqa: E402
                             locate_break, prove, prove_by_quorum)
from scripts.hosts import this_host                                  # noqa: E402
from scripts.measure import summarise                                # noqa: E402
from zk.commit import Pedersen                                       # noqa: E402
from zk.groups import make_group                                     # noqa: E402
from zk.threshold_sigma import deal                                  # noqa: E402


def timed(fn, repeats):
    out = []
    for _ in range(repeats):
        started = time.perf_counter()
        fn()
        out.append((time.perf_counter() - started) * 1e3)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+",
                    default=[16, 64, 256, 1024, 4096])
    ap.add_argument("--repeats", type=int, default=9)
    ap.add_argument("--parties", type=int, default=7)
    ap.add_argument("--threshold", type=int, default=2)
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts" / "reconcile.json")
    args = ap.parse_args()

    group = make_group("ed25519")
    key = Pedersen(group, b"qomm:defmi:v1").with_value_generator(asset_tag(group, 7))
    out = {"host": this_host(), "group": "ed25519",
           "note": "balances carry an asset tag, which is what a real one does",
           "scaling": [], "quorum": [], "locating": []}

    for n in args.sizes:
        rng = random.Random(n)
        values = [rng.randrange(1, 10_000) for _ in range(n)]
        blindings = [key.random_blinding() for _ in range(n)]
        commitments = [key.commit(v, r) for v, r in zip(values, blindings)]
        attestation = Attestation(register="a book of record", account="omnibus",
                                  asset="an instrument", total=sum(values),
                                  as_of="2026-08-22T09:00Z")
        built = None

        def build():
            nonlocal built
            built = prove(key, commitments, blindings, attestation)

        build_ms = timed(build, args.repeats)
        check_ms = timed(lambda: check(key, commitments, built), args.repeats)
        ok, _ = check(key, commitments, built)
        out["scaling"].append({
            "positions": n, "verified": ok,
            "prove": summarise(build_ms), "check": summarise(check_ms),
            "wire_bytes": len(group.encode(built.proof.commitment_t)) + 64,
        })

        # the same statement with nobody holding the aggregate blinding
        shares = deal(key, 0, sum(blindings) % group.order,
                      parties=list(range(1, args.parties + 1)),
                      threshold=args.threshold)
        quorum = list(range(1, args.threshold + 2))
        joint = None

        def build_joint():
            nonlocal joint
            joint = prove_by_quorum(key, commitments, shares, quorum, attestation)

        joint_ms = timed(build_joint, args.repeats)
        out["quorum"].append({
            "positions": n, "quorum": quorum, "of": args.parties,
            "assemble": summarise(joint_ms),
            "verified": check(key, commitments, joint)[0],
        })

        # and what finding a break costs, which is the number that is not free
        register = list(values)
        register[n // 3] += 5
        started = time.perf_counter()
        search = locate_break(key, commitments, blindings,
                              claimed=lambda a, b: sum(register[a:b]),
                              expected=sum(register))
        search_ms = (time.perf_counter() - started) * 1e3
        per_position = None
        started = time.perf_counter()
        per_position = check_positions(key, commitments, blindings, register)
        per_position_ms = (time.perf_counter() - started) * 1e3
        out["locating"].append({
            "positions": n, "found": search.found, "planted": n // 3,
            "sub_range_proofs": search.proofs,
            "two_log_n_plus_one": 2 * (n.bit_length() - 1) + 1,
            "subtotals_made_public": len(search.ranges_made_public),
            "narrowest_range": min(h - l for l, h, _ in search.ranges_made_public),
            "ms": round(search_ms, 1),
            "per_position_register": {
                "found": per_position, "ms": round(per_position_ms, 1),
                "disclosed": 0,
            },
        })
        print(f"n={n:5d}  prove {out['scaling'][-1]['prove']['median']:.2f} ms  "
              f"check {out['scaling'][-1]['check']['median']:.2f} ms  "
              f"quorum {out['quorum'][-1]['assemble']['median']:.2f} ms  "
              f"locate {search.proofs} proofs", flush=True)

    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
