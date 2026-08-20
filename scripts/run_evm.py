#!/usr/bin/env python3
"""What a settlement verification would cost on a chain with no curve25519.

The paper carried a figure for this --- eight to eleven verifications a second,
237 to 318 thousand gas --- with no artifact behind it. This is the artifact,
and it does not agree.

The measurement is deliberately not "implement the verifier in Solidity". That
would be measuring a different program, written by a different hand, and the
number would say as much about the port as about the machine. What is measured
instead is the *unit*: one curve25519 scalar multiplication, on a real EVM, in
an implementation checked against RFC 8032. The verification cost is composed
from that and from how many such multiplications a verification is worth, which
the Rust harness already reports as a ratio of two of its own timings.

Composing is the conservative direction. `curve25519-dalek` verifies a range
proof with a multiscalar multiplication, which does n terms far cheaper than n
independent multiplications; so the term count is larger than the equivalent
count used here, and a naive EVM port would pay for the terms. The figure below
is therefore a floor.

The block gas limit is read from a node rather than remembered, because it is
the number that decides whether the answer is "expensive" or "impossible" and
it has moved every year.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def block_gas_limit(rpc: str) -> tuple[int, int, int]:
    """The current limit, and the block it was read from."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1,
                       "method": "eth_getBlockByNumber",
                       "params": ["latest", False]}).encode()
    request = urllib.request.Request(
        rpc, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.loads(response.read())["result"]
    return (int(result["gasLimit"], 16), int(result["gasUsed"], 16),
            int(result["number"], 16))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:8545",
                    help="an Ethereum node, for the current block gas limit")
    ap.add_argument("--out", type=Path,
                    default=ROOT / "artifacts" / "evm_settlement.json")
    args = ap.parse_args()

    gas_path = ROOT / "artifacts" / "evm_gas.json"
    run = subprocess.run(["forge", "test"], cwd=ROOT / "evm",
                         capture_output=True, text=True)
    if run.returncode != 0:
        print(run.stdout[-2000:], file=sys.stderr)
        print("forge test failed; the gas figure is only worth having if the "
              "implementation still matches the reference vectors.",
              file=sys.stderr)
        return 1
    if not gas_path.exists():
        print(f"{gas_path} was not written; run `forge test` in evm/.",
              file=sys.stderr)
        return 1
    gas = json.loads(gas_path.read_text())

    rust_path = ROOT / "artifacts" / "rust_bench.json"
    if not rust_path.exists():
        print("artifacts/rust_bench.json is missing; run `make rust-bench` "
              "first --- the operation count comes from it.", file=sys.stderr)
        return 1
    rust = json.loads(rust_path.read_text())
    calibration = rust["calibration"]["scalar_mult_us"]

    try:
        limit, used, height = block_gas_limit(args.rpc)
    except (urllib.error.URLError, OSError, KeyError, TimeoutError) as exc:
        print(f"no Ethereum node at {args.rpc} ({exc}). The block gas limit is "
              "what decides whether this is expensive or impossible, so it is "
              "read rather than assumed: open a tunnel to an archive node and "
              "pass --rpc.", file=sys.stderr)
        return 1

    rows = []
    for row in rust["scaling"]:
        equivalents = row["settle_ms"] * 1000.0 / calibration
        total = equivalents * gas["gas"]
        rows.append({
            "bits": row["bits"],
            "settle_ms": row["settle_ms"],
            "scalar_mult_equivalents": round(equivalents, 1),
            "gas": round(total),
            "blocks": round(total / limit, 2),
            "per_second_at_12s_blocks": round(limit / total / 12.0, 4),
        })

    out = {
        "host": rust["host"],
        "unit": gas,
        "operation_count_from": {
            "artifact": "rust_bench.json",
            "host": rust["host"],
            "scalar_mult_us": calibration,
            "note": "an equivalent count, from settle time over one scalar "
                    "multiplication on the same machine. A floor: the verifier "
                    "batches its terms and the EVM would not.",
        },
        "chain": {
            "network": "ethereum mainnet",
            "block": height,
            "gas_limit": limit,
            "gas_used": used,
        },
        "scaling": rows,
    }
    args.out.write_text(json.dumps(out, indent=2) + "\n")
    print(f"one scalar multiplication: {gas['gas']:,} gas")
    print(f"block {height:,}: limit {limit:,}, used {used:,}")
    for row in rows:
        print(f"  {row['bits']:2} bits  {row['scalar_mult_equivalents']:6.1f} "
              f"scalar mults  {row['gas']:,} gas  "
              f"{row['blocks']:.2f} blocks  "
              f"{row['per_second_at_12s_blocks']:.4f} settlements/s")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
