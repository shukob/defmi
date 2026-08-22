#!/usr/bin/env python3
"""What one slice of a wallet costs to hand out, and what the holder can reach.

The interesting numbers here are not the milliseconds. They are the columns
saying how much of the pool a scope's key reaches, because the whole point of
moving the scoping into the address is that the answer is "its own notes and
nothing else" rather than "everything, forever".
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from defmi.assets import asset_tag                                  # noqa: E402
from defmi.notes import NoteLedger                                  # noqa: E402
from defmi.viewing import (ScopedWallet, check_grant, scan_scope,   # noqa: E402
                           total_seen)
from scripts.hosts import this_host                                 # noqa: E402
from scripts.measure import summarise                               # noqa: E402
from zk.commit import Pedersen                                      # noqa: E402
from zk.groups import make_group                                    # noqa: E402

NOW = 1_780_000_000


def timed(fn, repeats):
    out = []
    for _ in range(repeats):
        started = time.perf_counter()
        fn()
        out.append((time.perf_counter() - started) * 1e3)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pools", type=int, nargs="+", default=[64, 256, 1024])
    ap.add_argument("--scopes", type=int, default=4)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts" / "viewing.json")
    args = ap.parse_args()

    group = make_group("ed25519")
    key = Pedersen(group, b"qomm:defmi:note:v1")
    asset_key = key.with_value_generator(asset_tag(group, 3))
    out = {"host": this_host(), "group": "ed25519", "scopes": args.scopes,
           "scaling": [], "grant": {}}

    owner = ScopedWallet(group)
    scope_names = [f"2026Q{i + 1}" for i in range(args.scopes)]

    grant = owner.grant(scope_names[0], "an auditor", issued_at=NOW)
    out["grant"] = {
        "build": summarise(timed(
            lambda: owner.grant(scope_names[0], "an auditor", issued_at=NOW),
            max(args.repeats, 15))),
        "check": summarise(timed(
            lambda: check_grant(group, grant, owner.public_identity, now=NOW + 1),
            max(args.repeats, 15))),
        "expired_is_refused": not check_grant(
            group, grant, owner.public_identity, now=NOW + 400 * 86_400)[0],
        "wrong_owner_is_refused": not check_grant(
            group, grant, ScopedWallet(group).public_identity, now=NOW + 1)[0],
    }

    for pool_size in args.pools:
        ledger = NoteLedger(group, key)
        rng = random.Random(pool_size)
        planted = {scope: 0 for scope in scope_names}
        stranger = ScopedWallet(group)
        for i in range(pool_size):
            if i % (args.scopes + 1) == args.scopes:      # somebody else's notes
                note, _, _ = ledger.build_note(stranger.address("theirs"),
                                               rng.randrange(1, 500), asset_key,
                                               rng.randrange(group.order))
            else:
                scope = scope_names[i % (args.scopes + 1)]
                value = rng.randrange(1, 500)
                note, _, _ = ledger.build_note(owner.address(scope), value,
                                               asset_key, rng.randrange(group.order))
                planted[scope] += value
            ledger.add(note)

        viewer = owner.grant(scope_names[0], "an auditor", issued_at=NOW).viewer(group)
        seen = None

        def scan():
            nonlocal seen
            seen = scan_scope(ledger, viewer, asset_key)

        scan_ms = timed(scan, args.repeats)
        row = {
            "pool": pool_size,
            "scan": summarise(scan_ms),
            "per_note_ms": round(min(scan_ms) / pool_size, 4),
            "notes_reached": len(seen),
            "notes_in_pool": pool_size,
            "fraction_reached": round(len(seen) / pool_size, 4),
            "total_seen": total_seen(seen),
            "total_planted_in_that_scope": planted[scope_names[0]],
            "sees_exactly_its_scope": total_seen(seen) == planted[scope_names[0]],
            "serials_recovered": sum(1 for o in seen.values() if o.serial != -1),
        }
        out["scaling"].append(row)
        print(f"pool={pool_size:5d}  scan {row['scan']['median']:7.1f} ms "
              f"({row['per_note_ms']} ms/note)  reached {row['notes_reached']:4d} "
              f"of {pool_size} = {row['fraction_reached']:.1%}  "
              f"exact={row['sees_exactly_its_scope']}  "
              f"serials={row['serials_recovered']}", flush=True)

    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
