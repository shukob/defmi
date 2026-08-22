#!/usr/bin/env python3
"""What novation costs, and what it buys that the batch attestation did not.

`DEFMI.md` section 4 already measured the arm this is about. Netting the rails
saved 1.73x because 26.5 ms of every order is the payment instruction, which
does not net; replacing per-trade instructions with one attestation over the
cycle removed it and gave 17.95x --- and the note beside that number said what
it cost, that the split between participants becomes attested rather than
verified.

So the question here is **not** whether novation makes netting faster. The
speed was already there. It is whether novation makes that arm defensible, and
what the defence costs.

Three arms, the first two being the ones already published:

    net-net              an instruction verified per trade
    net-net+attested     one attestation over the cycle. Fast, and nobody is
                         named and nothing is behind it
    DeCCP                the same, with the trades novated first: every edge
                         rewritten to touch a named clearing house, the house's
                         book checked flat, and the attestation signed by a
                         provider whose own capital is a tranche of the waterfall

The first two are run by the harness that produced the published table, so the
comparison is against the same code rather than against a remembered figure.
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

from defmi.assets import asset_tag                                   # noqa: E402
from defmi.ccp import (Attestation, ClearingProvider, ClearingRegistry,  # noqa: E402
                       Obligation, check_novation, for_provider,
                       net_positions)
from defmi.credit import grant_credit                                # noqa: E402
from defmi.netting import NettingMode                                # noqa: E402
from scripts.hosts import this_host                                  # noqa: E402
from scripts.measure import summarise                                # noqa: E402
from scripts.run_defmi import one_cycle                              # noqa: E402
from zk.commit import Pedersen                                       # noqa: E402
from zk.groups import make_group                                     # noqa: E402


def clearing_arm(group, key, *, trades: int, participants: int, seed: int) -> dict:
    """Novate a cycle's worth of obligations and check every part anyone can."""
    rng = random.Random(seed)
    house = ClearingProvider("DeCCP-A", b"house-a", group, key)
    members = [f"p{i}".encode() for i in range(participants)]

    edges = []
    for _ in range(trades):
        payer, payee = rng.sample(members, 2)
        edges.append(Obligation(payer, payee, "an instrument",
                                key.commit(rng.randrange(1, 1000),
                                           key.random_blinding())))

    started = time.perf_counter()
    novation = house.novate(edges)
    novate_ms = (time.perf_counter() - started) * 1e3

    started = time.perf_counter()
    attestation = house.attest(novation, cycle=b"cycle-1")
    attest_ms = (time.perf_counter() - started) * 1e3

    # the provider is admitted only with margin posted and a tranche of its own
    margin = grant_credit(key, handle=house.handle, rail="cash", cap=5_000,
                          cap_blinding=key.random_blinding(), collateral=20_000,
                          collateral_blinding=key.random_blinding(),
                          haircut_bp=1_000, granted_at=1)
    waterfall = for_provider(
        "DeCCP-A",
        defaulter_margin=key.commit(1_000, key.random_blinding()),
        defaulter_fund=key.commit(500, key.random_blinding()),
        provider_capital=key.commit(2_000, key.random_blinding()),
        mutualised=key.commit(9_000, key.random_blinding()))
    registry = ClearingRegistry(group, key)
    admitted, why = registry.admit(house, margin=margin, waterfall=waterfall)

    started = time.perf_counter()
    ok, reason = registry.check_cycle(attestation, novation)
    check_ms = (time.perf_counter() - started) * 1e3

    started = time.perf_counter()
    nets = net_positions(group, novation)
    nets_ms = (time.perf_counter() - started) * 1e3

    return {"trades": trades, "participants": participants,
            "provider_admitted": admitted, "admit_detail": why,
            "novate_ms": novate_ms, "attest_ms": attest_ms,
            "check_ms": check_ms, "net_positions_ms": nets_ms,
            "verified": ok, "reason": reason,
            "edges_before": novation.edges, "edges_after": len(novation.after),
            "book_flat_without_a_proof": ok,
            "novate_us_per_trade": round(novate_ms / trades * 1000, 2),
            "check_us_per_trade": round(check_ms / trades * 1000, 2),
            "participants_with_a_net": len(nets)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trades", type=int, nargs="+", default=[16, 64, 256])
    ap.add_argument("--participants", type=int, default=8)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts" / "deccp.json")
    args = ap.parse_args()

    group = make_group("ed25519")
    key = Pedersen(group, b"qomm:defmi:v1").with_value_generator(asset_tag(group, 7))
    out = {"host": this_host(), "group": "ed25519",
           "participants": args.participants, "rows": []}

    for trades in args.trades:
        # the two published arms, from the harness that published them
        plain = [one_cycle(group, NettingMode.NET_NET, trades=trades,
                           participants=args.participants, attest=False,
                           seed=s) for s in range(args.repeats)]
        attested = [one_cycle(group, NettingMode.NET_NET, trades=trades,
                              participants=args.participants, attest=True,
                              seed=s) for s in range(args.repeats)]
        clearing = [clearing_arm(group, key, trades=trades,
                                 participants=args.participants, seed=s)
                    for s in range(args.repeats)]

        plain_total = summarise([r["verify_total_ms"] for r in plain])
        attested_total = summarise([r["verify_total_ms"] for r in attested])
        # what DeCCP adds to the attested arm: novation, its check, and the
        # provider's signature. The close is the attested arm's close.
        added = summarise([r["novate_ms"] + r["check_ms"] + r["attest_ms"]
                           for r in clearing])
        row = {
            "trades": trades,
            "net_net": plain_total,
            "net_net_attested": attested_total,
            "deccp_added_to_attested": added,
            "deccp_total": attested_total["median"] + added["median"],
            "speedup_attested_vs_plain": round(
                plain_total["median"] / attested_total["median"], 2),
            "speedup_deccp_vs_plain": round(
                plain_total["median"] / (attested_total["median"] + added["median"]), 2),
            "novate_us_per_trade": clearing[0]["novate_us_per_trade"],
            "check_us_per_trade": clearing[0]["check_us_per_trade"],
            "verify_per_order_ms_plain": round(
                sum(r["verify_per_order_ms"] for r in plain) / len(plain), 2),
            "book_flat_without_a_proof": all(r["book_flat_without_a_proof"]
                                             for r in clearing),
            "edges": {"before": clearing[0]["edges_before"],
                      "after": clearing[0]["edges_after"]},
        }
        out["rows"].append(row)
        print(f"trades={trades:5d}  net-net {plain_total['median']:8.1f} ms  "
              f"attested {attested_total['median']:7.1f} ms  "
              f"DeCCP {row['deccp_total']:7.1f} ms  "
              f"({row['speedup_deccp_vs_plain']}x vs net-net, "
              f"novation {row['novate_us_per_trade']} us/trade)", flush=True)

    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
