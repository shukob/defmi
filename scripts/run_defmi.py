#!/usr/bin/env python3
"""Measure DeFMI: what it costs to settle something the ledger cannot read.

Three questions, in the order they matter for deployment.

1. Where does the time go? If range proofs dominate, the ledger's balance width
   is the only parameter worth arguing about.
2. Is the cost linear in that width? The proof is a bit decomposition, so it
   should be, and a measured slope tells us what a narrower rail actually buys.
3. What throughput does a settlement node have, and does the work parallelise?
   Verification of independent packages is embarrassingly parallel; if it scales
   with cores then a node is provisioned, not redesigned.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import multiprocessing
import platform
import secrets
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from defmi.assets import AssetRegistry, BlindedTag                            # noqa: E402
from defmi.ledger import ConfidentialLedger                                   # noqa: E402
from defmi.credit import (                                                    # noqa: E402
    DefaultWaterfall, Tranche, check_credit, grant_credit,
)
from defmi.netting import (                                                   # noqa: E402
    BatchAttestation, NettingCycle, NettingMode, Order, PositionBook, Rejected,
)
from defmi.note_settlement import NoteDefmi, build_note_package               # noqa: E402
from defmi.notes import NoteLedger, Wallet                                    # noqa: E402
from defmi.settlement import Defmi, build_package                             # noqa: E402
from zk.commit import (                                                       # noqa: E402
    Pedersen, prove_bounded, prove_product, verify_bounded,
)
from zk.groups import make_group                                              # noqa: E402
from zk.zkpi import InstructionIssuer, SettlementVenue                        # noqa: E402

from scripts.hosts import this_host
from scripts.measure import exact, render, summarise           # noqa: E402                                          # noqa: E402

QTY, PRICE = 100, 99_990


def trade_for(bits: int) -> tuple[int, int]:
    """A trade that fits inside a rail of this width.

    Cost depends on the width of the range, never on the value inside it, so
    shrinking the trade to fit a narrow rail does not distort the comparison ---
    it just keeps the proof statement true.
    """
    ceiling = (1 << bits) - 1
    quantity = min(QTY, max(1, ceiling // 2))
    price = min(PRICE, max(1, (ceiling // 2) // quantity))
    return quantity, price


def fresh(group, bits: int):
    """A venue and two rails whose balances live in [0, 2^bits)."""
    key = Pedersen(group, b"qomm:defmi:v1")
    defmi = Defmi(group, key, venue=SettlementVenue(group, key))
    ceiling = (1 << bits) - 1
    defmi.securities = ConfidentialLedger(group, key, max_balance=ceiling)
    defmi.cash = ConfidentialLedger(group, key, max_balance=ceiling)
    quantity, price = trade_for(bits)
    sec = (min(max(5_000, quantity), ceiling), key.random_blinding())
    cash = (min(max(50_000_000, quantity * price), ceiling), key.random_blinding())
    defmi.securities.open_account(b"sec:seller", key.commit(*sec))
    defmi.securities.open_account(b"sec:buyer", key.commit(0, key.random_blinding()))
    defmi.cash.open_account(b"cash:buyer", key.commit(*cash))
    defmi.cash.open_account(b"cash:seller", key.commit(0, key.random_blinding()))
    return key, defmi, InstructionIssuer(group, key), sec, cash


def build_for(group, key, defmi, issuer, sec, cash, bits: int,
              sec_bits: int | None = None):
    """Issue an instruction and assemble the matching DvP package."""
    quantity, price = trade_for(min(bits, sec_bits or bits))
    instruction, aux = issuer.issue(
        asset=3, amount=quantity, price=price,
        payer_handle=group.hash_to_point(b"entity-buyer"),
        payee_handle=group.hash_to_point(b"entity-seller"),
        deadline=1_500, nonce=secrets.token_bytes(32), quote_key=1_599_845,
        nodes=list(range(1, 8)), threshold=2, quorum=[1, 2, 3])
    package, _ = build_package(
        group, key, instruction=instruction, securities=defmi.securities,
        cash=defmi.cash, securities_from=b"sec:seller", securities_to=b"sec:buyer",
        cash_from=b"cash:buyer", cash_to=b"cash:seller",
        quantity=quantity, price=price,
        seller_securities_balance=sec[0], seller_securities_blinding=sec[1],
        buyer_cash_balance=cash[0], buyer_cash_blinding=cash[1],
        instruction_amount_blinding=aux["blindings"]["amount"],
        instruction_price_blinding=aux["blindings"]["price"])
    return package


def one_settlement(group, bits: int, quantity=None, price=None):
    key, defmi, issuer, sec, cash = fresh(group, bits)
    if quantity is None:
        quantity, price = trade_for(bits)
    t = time.perf_counter()
    instruction, aux = issuer.issue(
        asset=3, amount=quantity, price=price,
        payer_handle=group.hash_to_point(b"entity-buyer"),
        payee_handle=group.hash_to_point(b"entity-seller"),
        deadline=1_500, nonce=secrets.token_bytes(32), quote_key=1_599_845,
        nodes=list(range(1, 8)), threshold=2, quorum=[1, 2, 3])
    issue_ms = (time.perf_counter() - t) * 1e3

    t = time.perf_counter()
    package, _ = build_package(
        group, key, instruction=instruction, securities=defmi.securities,
        cash=defmi.cash, securities_from=b"sec:seller", securities_to=b"sec:buyer",
        cash_from=b"cash:buyer", cash_to=b"cash:seller",
        quantity=quantity, price=price,
        seller_securities_balance=sec[0], seller_securities_blinding=sec[1],
        buyer_cash_balance=cash[0], buyer_cash_blinding=cash[1],
        instruction_amount_blinding=aux["blindings"]["amount"],
        instruction_price_blinding=aux["blindings"]["price"])
    build_ms = (time.perf_counter() - t) * 1e3

    # The instruction check on its own, before the ledger is involved. The paper
    # states what share of a settlement is the zkPI and what share is the rails,
    # and that split is only honest if the two are timed separately.
    t = time.perf_counter()
    ok, reason = defmi.venue.verify(instruction, now=1_000)
    instruction_verify_ms = (time.perf_counter() - t) * 1e3
    assert ok, reason

    t = time.perf_counter()
    receipt = defmi.settle(package, now=1_000)
    settle_ms = (time.perf_counter() - t) * 1e3
    assert receipt.status == "settled", receipt.reason
    return issue_ms, build_ms, settle_ms, instruction_verify_ms, package


def split_settlement(group, sec_bits: int, cash_bits: int):
    """Two rails of different widths, which is what a real venue would run."""
    key = Pedersen(group, b"qomm:defmi:v1")
    defmi = Defmi(group, key, venue=SettlementVenue(group, key))
    defmi.securities = ConfidentialLedger(group, key, max_balance=(1 << sec_bits) - 1)
    defmi.cash = ConfidentialLedger(group, key, max_balance=(1 << cash_bits) - 1)
    quantity, price = trade_for(min(sec_bits, cash_bits))
    sec = (min(max(5_000, quantity), (1 << sec_bits) - 1), key.random_blinding())
    cash = (min(max(50_000_000, quantity * price), (1 << cash_bits) - 1),
            key.random_blinding())
    defmi.securities.open_account(b"sec:seller", key.commit(*sec))
    defmi.securities.open_account(b"sec:buyer", key.commit(0, key.random_blinding()))
    defmi.cash.open_account(b"cash:buyer", key.commit(*cash))
    defmi.cash.open_account(b"cash:seller", key.commit(0, key.random_blinding()))
    issuer = InstructionIssuer(group, key)
    t = time.perf_counter()
    package = build_for(group, key, defmi, issuer, sec, cash,
                        min(sec_bits, cash_bits))
    build_ms = (time.perf_counter() - t) * 1e3
    t = time.perf_counter()
    receipt = defmi.settle(package, now=1_000)
    settle_ms = (time.perf_counter() - t) * 1e3
    assert receipt.status == "settled", receipt.reason
    return build_ms, settle_ms, package_bytes(group, package)


def tagged_settlement(group, registry, asset: int, *, tag_asset: int | None = None,
                      carry_membership: bool = False, tagged: bool = True,
                      tag_override: tuple | None = None):
    """One settlement on a securities rail that hides which security it is.

    ``tag_asset`` different from ``asset`` is the cross-asset attempt: a payer
    holding one thing tries to move it under the disguise of another.
    """
    key = registry.key
    defmi = Defmi(group, key, venue=SettlementVenue(group, key))
    issuer = InstructionIssuer(group, key)
    asset_key = key.with_value_generator(registry.tags[asset]) if tagged else key
    sec = (5_000, key.random_blinding())
    cash = (50_000_000, key.random_blinding())
    defmi.securities.open_account(b"sec:seller", asset_key.commit(*sec))
    defmi.securities.open_account(b"sec:buyer", asset_key.commit(0, key.random_blinding()))
    defmi.cash.open_account(b"cash:buyer", key.commit(*cash))
    defmi.cash.open_account(b"cash:seller", key.commit(0, key.random_blinding()))

    tag, gamma = (None, 0)
    if tag_override is not None:
        tag, gamma = tag_override
    elif tagged:
        tag, gamma = registry.blind(tag_asset if tag_asset is not None else asset,
                                    prove=carry_membership)
    instruction, aux = issuer.issue(
        asset=asset, amount=QTY, price=PRICE,
        payer_handle=group.hash_to_point(b"entity-buyer"),
        payee_handle=group.hash_to_point(b"entity-seller"),
        deadline=1_500, nonce=secrets.token_bytes(32), quote_key=1_599_845,
        nodes=list(range(1, 8)), threshold=2, quorum=[1, 2, 3])
    t = time.perf_counter()
    package, _ = build_package(
        group, key, instruction=instruction, securities=defmi.securities,
        cash=defmi.cash, securities_from=b"sec:seller", securities_to=b"sec:buyer",
        cash_from=b"cash:buyer", cash_to=b"cash:seller", quantity=QTY, price=PRICE,
        seller_securities_balance=sec[0], seller_securities_blinding=sec[1],
        buyer_cash_balance=cash[0], buyer_cash_blinding=cash[1],
        instruction_amount_blinding=aux["blindings"]["amount"],
        instruction_price_blinding=aux["blindings"]["price"],
        securities_tag=tag, securities_gamma=gamma)
    build_ms = (time.perf_counter() - t) * 1e3
    t = time.perf_counter()
    receipt = defmi.settle(package, now=1_000)
    settle_ms = (time.perf_counter() - t) * 1e3
    return build_ms, settle_ms, receipt, package_bytes(group, package)


def asset_hiding(group, assets: int, repeats: int) -> dict:
    """What the disguise costs, and whether it actually holds."""
    key = Pedersen(group, b"qomm:defmi:v1")
    registry = AssetRegistry(group, key, assets)
    arms = {}
    for name, kwargs in (("plain", {"tagged": False}),
                         ("tagged", {}),
                         ("tagged_with_membership", {"carry_membership": True})):
        rows = [tagged_settlement(group, registry, 3, **kwargs) for _ in range(repeats)]
        assert all(r[2].status == "settled" for r in rows), rows[0][2].reason
        arms[name] = {"build": summarise(r[0] for r in rows),
                      "settle": summarise(r[1] for r in rows),
                      "package_bytes": rows[-1][3]}

    # every asset must produce the same bytes, or the disguise is decorative
    per_asset = {}
    for asset in range(min(assets, 8)):
        _, _, receipt, size = tagged_settlement(group, registry, asset)
        per_asset[asset] = {"status": receipt.status, "package_bytes": size}
    indistinguishable = len({(v["status"], v["package_bytes"])
                             for v in per_asset.values()}) == 1

    # and the disguise must not let a holder of one asset move another
    attacks = {}
    other = (3 + 1) % assets
    _, _, receipt, _ = tagged_settlement(group, registry, 3, tag_asset=other)
    attacks["registered_tag_wrong_asset"] = {"status": receipt.status,
                                             "reason": receipt.reason}
    forged = (BlindedTag(group.hash_to_point(b"not-a-listed-asset")), 7)
    _, _, receipt, _ = tagged_settlement(group, registry, 3, tag_override=forged)
    attacks["fabricated_tag"] = {"status": receipt.status, "reason": receipt.reason}

    issue = []
    for _ in range(repeats):
        t = time.perf_counter()
        tag, _ = registry.blind(3, prove=True)
        prove_ms = (time.perf_counter() - t) * 1e3
        t = time.perf_counter()
        assert registry.verify_membership(tag)
        issue.append((prove_ms, (time.perf_counter() - t) * 1e3))
    return {"assets": assets, "set_size": registry.size, "arms": arms,
            "per_asset": per_asset, "indistinguishable": indistinguishable,
            "attacks": attacks,
            "membership_prove": summarise(r[0] for r in issue),
            "membership_verify": summarise(r[1] for r in issue),
            "membership_bytes": arms["tagged_with_membership"]["package_bytes"]
                                - arms["tagged"]["package_bytes"]}


def note_spends(group, ring_sizes, repeats: int, pool_size: int) -> dict:
    """What an anonymity set costs.

    A note ledger buys unlinkability with a one-out-of-many proof over a ring of
    decoys, and the ring is the only knob: everything else about a spend is
    fixed. So the question a venue actually has to answer --- how large a set is
    affordable --- is exactly this table.
    """
    import random as _random

    key = Pedersen(group, b"qomm:defmi:v1")
    registry = AssetRegistry(group, key, 16)
    asset_key = key.with_value_generator(registry.tags[3])
    ledger = NoteLedger(group, key)
    alice, bob = Wallet(group), Wallet(group)
    mine = []
    for i in range(pool_size):
        owner = alice.address if i % 8 == 0 else Wallet(group).address
        note, _, _ = ledger.build_note(owner, 1_000 + i, asset_key)
        index = ledger.add(note)
        if i % 8 == 0:
            mine.append(index)

    t = time.perf_counter()
    found = ledger.scan(alice, asset_key)
    scan_ms = (time.perf_counter() - t) * 1e3
    assert set(found) == set(mine), "scanning did not recover exactly our notes"

    rows = []
    for size in ring_sizes:
        if size > pool_size:
            continue
        builds, checks, wire = [], [], 0
        for repeat in range(repeats):
            index = mine[repeat % len(mine)]
            opening = found[index]
            tag, gamma = registry.blind(3)
            ring = ledger.ring_for(index, size, _random.Random(repeat))
            t = time.perf_counter()
            proof, _, _ = ledger.build_spend(
                ring, index, opening, tag, gamma,
                [(bob.address, 400), (alice.address, opening.value - 400)])
            builds.append((time.perf_counter() - t) * 1e3)
            t = time.perf_counter()
            accepted, reason = ledger.check_spend(ring, proof)
            checks.append((time.perf_counter() - t) * 1e3)
            assert accepted, reason
            wire = _wire_size(group, proof)
        rows.append({"ring": size, "build": summarise(builds),
                     "check": summarise(checks), "wire_bytes": exact(wire)})
        print(f"  ring {size:4d}   build {render(rows[-1]['build'], 1)}  "
              f"check {render(rows[-1]['check'], 1)} ms   {wire:6d} B")

    # two payments to one address must share nothing on the wire
    first, _, _ = ledger.build_note(bob.address, 100, asset_key)
    second, _, _ = ledger.build_note(bob.address, 100, asset_key)
    unlinkable = (group.encode(ledger.commitment_of(first))
                  != group.encode(ledger.commitment_of(second))
                  and group.encode(first.ephemeral) != group.encode(second.ephemeral))

    return {"pool_size": pool_size, "rings": rows,
            "scan_ms": scan_ms, "scan_ms_per_note": scan_ms / pool_size,
            "outputs_unlinkable": unlinkable}


def note_settlements(group, ring_sizes, repeats: int) -> dict:
    """The same delivery-versus-payment, on note rails instead of accounts.

    Worth measuring rather than adding up: a note leg and an account leg both
    carry two range proofs, so the difference is only the ring proof, the serial
    proof and one extra cross-generator equality. Estimating it from the parts
    overstated it by more than a factor of two the first time we tried.
    """
    import random as _random

    rows = []
    for size in ring_sizes:
        builds, settles, wire = [], [], 0
        for repeat in range(repeats):
            key = Pedersen(group, b"qomm:defmi:v1")
            registry = AssetRegistry(group, key, 16)
            defmi = NoteDefmi(group, key, venue=SettlementVenue(group, key))
            issuer = InstructionIssuer(group, key)
            sec_key = key.with_value_generator(registry.tags[3])
            cash_key = key.with_value_generator(registry.tags[0])
            seller, buyer = Wallet(group), Wallet(group)
            for i in range(size):
                owner = seller.address if i == 0 else Wallet(group).address
                note, _, _ = defmi.securities.build_note(owner, 5_000, sec_key)
                defmi.securities.add(note)
                owner = buyer.address if i == 0 else Wallet(group).address
                note, _, _ = defmi.cash.build_note(owner, 50_000_000, cash_key)
                defmi.cash.add(note)
            sec_found = defmi.securities.scan(seller, sec_key)
            cash_found = defmi.cash.scan(buyer, cash_key)
            si, ci = next(iter(sec_found)), next(iter(cash_found))
            instruction, aux = issuer.issue(
                asset=3, amount=QTY, price=PRICE,
                payer_handle=group.hash_to_point(b"entity-buyer"),
                payee_handle=group.hash_to_point(b"entity-seller"),
                deadline=1_500, nonce=secrets.token_bytes(32), quote_key=1_599_845,
                nodes=list(range(1, 8)), threshold=2, quorum=[1, 2, 3])
            sec_tag, sec_gamma = registry.blind(3)
            cash_tag, cash_gamma = registry.blind(0)
            rng = _random.Random(repeat)
            t = time.perf_counter()
            package = build_note_package(
                group, key, instruction=instruction,
                securities=defmi.securities, cash=defmi.cash,
                securities_ring=defmi.securities.ring_for(si, size, rng),
                securities_index=si, securities_opening=sec_found[si],
                securities_tag=sec_tag, securities_gamma=sec_gamma,
                cash_ring=defmi.cash.ring_for(ci, size, rng), cash_index=ci,
                cash_opening=cash_found[ci], cash_tag=cash_tag, cash_gamma=cash_gamma,
                buyer_securities_address=buyer.address,
                seller_securities_address=seller.address,
                seller_cash_address=seller.address,
                buyer_cash_address=buyer.address,
                quantity=QTY, price=PRICE,
                instruction_amount_blinding=aux["blindings"]["amount"],
                instruction_price_blinding=aux["blindings"]["price"])
            builds.append((time.perf_counter() - t) * 1e3)
            t = time.perf_counter()
            receipt = defmi.settle(package, now=1_000)
            settles.append((time.perf_counter() - t) * 1e3)
            assert receipt.status == "settled", receipt.reason
            wire = package_bytes(group, package)
        rows.append({"ring": size, "build": summarise(builds),
                     "settle": summarise(settles), "package_bytes": exact(wire)})
        print(f"  ring {size:4d}   build {render(rows[-1]['build'], 1)}  "
              f"settle {render(rows[-1]['settle'], 1)} ms   {wire:6d} B")
    return {"rings": rows}


class _Holder:
    """A participant's own book. The cycle never sees any of it."""

    __slots__ = ("handle", "securities", "cash")

    def __init__(self, key, handle, securities, cash):
        self.handle = handle
        self.securities = [securities, key.random_blinding()]
        self.cash = [cash, key.random_blinding()]


def one_cycle(group, mode, *, trades: int, participants: int, attest: bool,
              seed: int) -> dict:
    """Run a whole netting cycle and separate the verifier's work from the payer's.

    The split is the point. A gross rail loads the settlement window with a cover
    proof per order; a net rail moves that to the close, where it is per
    participant; and a batch attestation takes the per-order instruction
    verification out altogether, which turns out to dominate the other two.
    """
    import random as _random

    key = Pedersen(group, b"qomm:defmi:v1")
    registry = AssetRegistry(group, key, 16)
    sec_tag, sec_gamma = registry.blind(3)
    cash_tag, cash_gamma = registry.blind(0)
    venue = SettlementVenue(group, key)
    cycle = NettingCycle(group, key, mode, sec_tag, sec_gamma, cash_tag, cash_gamma,
                         venue=venue, attest_batch=attest)
    issuer = InstructionIssuer(group, key)

    holders = {}
    for i in range(participants):
        handle = f"p{i}".encode()
        holder = _Holder(key, handle, 10_000_000, 100_000_000_000 % (1 << 40))
        holders[handle] = holder
        cycle.securities.open(handle, cycle.securities.tagged.commit(*holder.securities))
        cycle.cash.open(handle, cycle.cash.tagged.commit(*holder.cash))

    rng = _random.Random(seed)
    handles = list(holders)
    build_total = verify_total = 0.0
    admitted = refused = 0
    for _ in range(trades):
        seller, buyer = rng.sample(handles, 2)
        quantity, price = rng.randrange(10, 60), rng.randrange(90_000, 110_000)
        value = quantity * price
        instruction, aux = issuer.issue(
            asset=3, amount=quantity, price=price,
            payer_handle=group.hash_to_point(buyer),
            payee_handle=group.hash_to_point(seller),
            deadline=1_500, nonce=secrets.token_bytes(32), quote_key=1_599_845,
            nodes=list(range(1, 8)), threshold=2, quorum=[1, 2, 3])
        t = time.perf_counter()
        cash_blinding = key.random_blinding()
        cash_reference = key.commit(value, cash_blinding)
        value_proof = prove_product(
            key, instruction.price_commitment, price, aux["blindings"]["price"],
            quantity, aux["blindings"]["amount"], cash_blinding,
            b"QOMM:DEFMI:CYCLE:v1:value")
        sold, bought = holders[seller], holders[buyer]
        try:
            sec_blinding = key.random_blinding()
            sec_leg = cycle.securities.build_leg(
                seller, buyer, quantity, sec_blinding,
                sold.securities[0], sold.securities[1],
                instruction.amount_commitment, aux["blindings"]["amount"],
                b"QOMM:DEFMI:CYCLE:v1:sec")
            value_blinding = key.random_blinding()
            cash_leg = cycle.cash.build_leg(
                buyer, seller, value, value_blinding, bought.cash[0], bought.cash[1],
                cash_reference, cash_blinding, b"QOMM:DEFMI:CYCLE:v1:cash")
        except Rejected:
            refused += 1
            continue
        build_total += (time.perf_counter() - t) * 1e3
        order = Order(instruction, sec_leg, cash_leg, cash_reference, value_proof)
        t = time.perf_counter()
        accepted, _ = cycle.admit(order, now=1_000)
        verify_total += (time.perf_counter() - t) * 1e3
        if not accepted:
            refused += 1
            continue
        admitted += 1
        order_n = group.order
        sold.securities[0] -= quantity
        sold.securities[1] = (sold.securities[1] - sec_blinding) % order_n
        bought.securities[0] += quantity
        bought.securities[1] = (bought.securities[1] + sec_blinding) % order_n
        bought.cash[0] -= value
        bought.cash[1] = (bought.cash[1] - value_blinding) % order_n
        sold.cash[0] += value
        sold.cash[1] = (sold.cash[1] + value_blinding) % order_n

    coverages = {}
    t = time.perf_counter()
    for name, book, field in (("securities", cycle.securities, "securities"),
                              ("cash", cycle.cash, "cash")):
        if not book.net:
            continue
        coverages[name] = [
            book.build_coverage(handle, getattr(holder, field)[0],
                                getattr(holder, field)[1],
                                b"QOMM:DEFMI:CYCLE:v1:" + name.encode())
            for handle, holder in holders.items()]
    close_build = (time.perf_counter() - t) * 1e3
    attestation = (BatchAttestation(cycle.batch_digest(), b"", (1, 2, 3))
                   if attest else None)
    t = time.perf_counter()
    receipt = cycle.close(coverages, now=1_100, attestation=attestation)
    close_verify = (time.perf_counter() - t) * 1e3
    assert receipt.status == "closed", receipt.reason

    return {"mode": mode.value + ("+attested" if attest else ""),
            "trades": trades, "participants": participants,
            "admitted": admitted, "refused": refused,
            "verify_per_order_ms": verify_total / max(admitted, 1),
            "verify_orders_ms": verify_total, "verify_close_ms": close_verify,
            "verify_total_ms": verify_total + close_verify,
            "build_orders_ms": build_total, "build_close_ms": close_build}


def credit_and_waterfall(group, tranche_counts, repeats: int) -> dict:
    """What the two facilities cost, and where the cost lands.

    A credit line is granted once and consulted for free afterwards, so the only
    number that matters for throughput is that the cap does not change what an
    order costs. A waterfall runs once per default, so its cost is linear in the
    number of tranches and nobody should care very much.
    """
    key = Pedersen(group, b"qomm:defmi:v1")
    registry = AssetRegistry(group, key, 16)
    tag, gamma = registry.blind(3)
    book = PositionBook(group, key, tag, gamma, net=True, rail="securities")
    book.open(b"p0", book.tagged.commit(0, key.random_blinding()))

    grants, checks = [], []
    for _ in range(repeats):
        cap_blinding = key.random_blinding()
        t = time.perf_counter()
        line = grant_credit(book.tagged, handle=b"p0", rail="securities",
                            cap=300_000, cap_blinding=cap_blinding,
                            collateral=10_000_000,
                            collateral_blinding=key.random_blinding(),
                            haircut_bp=500, granted_at=1_000)
        grants.append((time.perf_counter() - t) * 1e3)
        t = time.perf_counter()
        assert check_credit(book.tagged, line)[0]
        checks.append((time.perf_counter() - t) * 1e3)
    assert book.grant(line)[0]

    # a coverage proof with and without a cap: the cap must not change its cost
    position, blinding = -250_000, key.random_blinding()
    book.positions[b"p0"].commitment = book.tagged.commit(position, blinding)
    capped, plain = [], []
    for _ in range(repeats):
        t = time.perf_counter()
        coverage = book.build_coverage(b"p0", position, blinding,
                                       b"QOMM:DEFMI:CYCLE:v1", cap_value=300_000,
                                       cap_blinding=cap_blinding)
        capped.append((time.perf_counter() - t) * 1e3)
        assert book.check_coverage(coverage, b"QOMM:DEFMI:CYCLE:v1")[0]
    bare = PositionBook(group, key, tag, gamma, net=True, rail="securities")
    bare.open(b"p0", bare.tagged.commit(250_000, blinding))
    for _ in range(repeats):
        t = time.perf_counter()
        bare.build_coverage(b"p0", 250_000, blinding, b"QOMM:DEFMI:CYCLE:v1")
        plain.append((time.perf_counter() - t) * 1e3)

    falls = []
    for count in tranche_counts:
        balances = [300, 200, 500] + [5_000] * (count - 3) if count >= 3 \
            else [300] * count
        blindings = [key.random_blinding() for _ in balances]
        names = [f"tranche {i}" for i in range(count)]
        waterfall = DefaultWaterfall(
            group, key, [Tranche(n, key.commit(b, r))
                         for n, b, r in zip(names, balances, blindings)])
        shortfall = sum(balances) // 2
        builds, verifies = [], []
        for _ in range(repeats):
            t = time.perf_counter()
            resolution, amounts = waterfall.build(
                shortfall=shortfall, shortfall_blinding=key.random_blinding(),
                balances=balances, blindings=blindings)
            builds.append((time.perf_counter() - t) * 1e3)
            t = time.perf_counter()
            accepted, reason = waterfall.check(resolution)
            verifies.append((time.perf_counter() - t) * 1e3)
            assert accepted, reason
        falls.append({"tranches": count, "build": summarise(builds),
                      "check": summarise(verifies),
                      "drawn": amounts})
        print(f"  waterfall over {count:2d} tranches   "
              f"build {render(falls[-1]['build'], 1)}"
              f"  check {render(falls[-1]['check'], 1)} ms")

    row = {"grant": summarise(grants),
           "check": summarise(checks),
           "coverage_capped": summarise(capped),
           "coverage_plain": summarise(plain),
           "waterfall": falls}
    print(f"  credit line: grant {render(row['grant'], 1)} / "
          f"check {render(row['check'], 1)} ms, once")
    print(f"  coverage proof: {render(row['coverage_plain'], 1)} without a cap, "
          f"{render(row['coverage_capped'], 1)} ms with one")
    return row


def netting(group, trade_counts, participant_counts, repeats: int) -> dict:
    arms = [(m, False) for m in NettingMode] + [(NettingMode.NET_NET, True)]
    rows = []
    for trades in trade_counts:
        for participants in participant_counts:
            base = None
            for mode, attest in arms:
                runs = [one_cycle(group, mode, trades=trades,
                                  participants=participants, attest=attest, seed=r)
                        for r in range(repeats)]
                row = {k.removesuffix("_ms"): summarise(r[k] for r in runs)
                       for k in ("verify_per_order_ms", "verify_orders_ms",
                                 "verify_close_ms", "verify_total_ms",
                                 "build_orders_ms", "build_close_ms")}
                row.update(mode=runs[0]["mode"], trades=trades,
                           participants=participants,
                           admitted=runs[0]["admitted"], refused=runs[0]["refused"])
                total = row["verify_total"]["mean"]
                base = base or total
                row["speedup_vs_gross_gross"] = base / total
                rows.append(row)
                print(f"  N={trades:4d} P={participants:3d}  {row['mode']:18s}"
                      f" order {render(row['verify_per_order'], 2)}"
                      f"  close {render(row['verify_close'], 1)}"
                      f"  verify total {render(row['verify_total'], 1)} ms"
                      f"  {row['speedup_vs_gross_gross']:5.2f}x")
    return {"rows": rows}


def calibration(group, repeats: int) -> dict:
    """A fixed yardstick recorded next to the results.

    Two runs of this script a few hours apart disagreed by a factor of 1.5 on
    the same machine, and nothing in the JSON said so. Everything below is
    reported in milliseconds, so a reader --- including a later version of us
    --- needs a way to tell whether the machine was in the same state. A single
    scalar multiplication and a single 40-bit range proof are enough: they are
    the two operations everything here is built from, so if they match, the
    rest is comparable, and if they do not, nothing is.
    """
    key = Pedersen(group, b"qomm:defmi:calib")
    point = group.hash_to_point(b"calibration")
    scalars = []
    for _ in range(max(repeats, 50)):
        t = time.perf_counter()
        group.point_pow(point, 12345)
        scalars.append((time.perf_counter() - t) * 1e6)
    ranges = []
    for _ in range(repeats):
        blinding = key.random_blinding()
        t = time.perf_counter()
        prove_bounded(key, 1234, blinding, 0, (1 << 40) - 1, b"calib")
        ranges.append((time.perf_counter() - t) * 1e3)
    # The yardstick itself is a measurement, so it carries its own spread: a
    # calibration whose repeats disagree says the machine moved during them.
    return {"scalar_mult_us": summarise(scalars),
            "range_proof_40bit_ms": summarise(ranges)}


def range_share(group, bits: int, repeats: int) -> dict:
    """How much of a leg is the range proof alone."""
    key = Pedersen(group, b"qomm:defmi:v1")
    ceiling = (1 << bits) - 1
    prove, verify = [], []
    for _ in range(repeats):
        blinding = key.random_blinding()
        t = time.perf_counter()
        commitment, proof, _ = prove_bounded(key, min(1_234, ceiling), blinding, 0, ceiling, b"m")
        prove.append((time.perf_counter() - t) * 1e3)
        t = time.perf_counter()
        assert verify_bounded(key, commitment, proof, 0, ceiling, b"m")
        verify.append((time.perf_counter() - t) * 1e3)
    return {"bits": bits, "prove": summarise(prove), "verify": summarise(verify)}


def _verify_job(payload):
    """Verification only: the counterparties prove, the node checks.

    Packages are built inside the worker before the clock starts, because a
    settlement node never does that work --- charging it for proving would
    overstate what a node costs to run. The barrier matters: without it a worker
    that finishes proving early verifies on an idle machine while the others are
    still proving, and the measurement flatters itself. Top-level so it survives
    pickling.
    """
    bits, count, barrier = payload
    group = make_group("ed25519")
    prepared = []
    for _ in range(count):
        key, defmi, issuer, sec, cash = fresh(group, bits)
        prepared.append((defmi, build_for(group, key, defmi, issuer, sec, cash, bits)))
    # every worker waits here, so the timed section is the only thing running and
    # all of them contend for the machine over the same interval
    if barrier is not None:
        barrier.wait()
    t = time.perf_counter()
    for defmi, package in prepared:
        assert defmi.settle(package, now=1_000).status == "settled"
    return time.perf_counter() - t


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="artifacts/defmi.json")
    ap.add_argument("--bits", type=int, nargs="+", default=[16, 24, 32, 40, 48])
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4, 8])
    ap.add_argument("--parallel-each", type=int, default=3)
    ap.add_argument("--parallel-repeats", type=int, default=5)
    ap.add_argument("--assets", type=int, nargs="+", default=[4, 16, 64])
    ap.add_argument("--rings", type=int, nargs="+", default=[2, 4, 8, 16, 32, 64, 128])
    ap.add_argument("--pool", type=int, default=256)
    ap.add_argument("--trades", type=int, nargs="+", default=[16, 64])
    ap.add_argument("--parties", type=int, nargs="+", default=[8])
    ap.add_argument("--tranches", type=int, nargs="+", default=[2, 4, 8, 16])
    ap.add_argument("--split", type=lambda s: tuple(int(x) for x in s.split(":")),
                    nargs="+", default=[(48, 48), (32, 48), (24, 48), (32, 40)],
                    help="securities_bits:cash_bits pairs")
    args = ap.parse_args()

    group = make_group("ed25519")
    result: dict = {
        "host": this_host(), "python": platform.python_version(),
        "group": "ed25519", "quantity": QTY, "price": PRICE,
    }

    result["calibration"] = calibration(group, args.repeats)
    print(f"calibration: scalar mult "
          f"{render(result['calibration']['scalar_mult_us'], 1, ' us')}, "
          f"40-bit range proof "
          f"{render(result['calibration']['range_proof_40bit_ms'], 2, ' ms')}")
    print("  (compare against this before comparing any number below)\n")

    print("scaling in the ledger balance width")
    scaling = []
    for bits in args.bits:
        issues, builds, settles, checks, size = [], [], [], [], 0
        for _ in range(args.repeats):
            i, b, s, v, package = one_settlement(group, bits)
            issues.append(i); builds.append(b); settles.append(s); checks.append(v)
            size = package_bytes(group, package)
        row = {"bits": bits,
               "issue": summarise(issues),
               "build": summarise(builds),
               "settle": summarise(settles),
               "instruction_verify": summarise(checks),
               # A function of the width, identical on every run.
               "package_bytes": exact(size),
               "range_only": range_share(group, bits, args.repeats)}
        scaling.append(row)
        print(f"  {bits:2d} bits  issue {render(row['issue'], 1)}"
              f"  build {render(row['build'], 1)}"
              f"  settle {render(row['settle'], 1)}"
              f"  of which instruction {render(row['instruction_verify'], 1)} ms"
              f"   package {size:6d} B")
    result["scaling"] = scaling

    print("\nnetting cycles: gross-gross, gross-net, net-net, and net-net attested")
    result["netting"] = netting(group, args.trades, args.parties,
                                max(2, args.repeats // 5))

    print("\nintraday credit and the default waterfall")
    result["credit"] = credit_and_waterfall(group, args.tranches, args.repeats)

    print("\nnote ledger: what an anonymity set costs")
    result["notes"] = note_spends(group, args.rings, args.repeats, args.pool)
    n = result["notes"]
    print(f"  scanning the pool: {n['scan_ms']:.1f} ms for {n['pool_size']} notes "
          f"({n['scan_ms_per_note']:.3f} ms each)   "
          f"outputs unlinkable: {n['outputs_unlinkable']}")

    print("\nnote rails end to end: the same DvP without accounts")
    result["note_settlement"] = note_settlements(
        group, [r for r in args.rings if r <= 64], max(3, args.repeats // 3))

    print("\nasset hiding: settling without learning which security it is")
    hiding = []
    for assets in args.assets:
        row = asset_hiding(group, assets, args.repeats)
        hiding.append(row)
        plain, tag = row["arms"]["plain"], row["arms"]["tagged"]
        # The tag's time cost is quoted against the spread of the untagged arm,
        # because a difference smaller than that spread is not a difference.
        shift = 100 * (tag['build']['mean'] - plain['build']['mean']) / plain['build']['mean']
        print(f"  {assets:3d} assets  build {render(plain['build'], 1)} -> "
              f"{render(tag['build'], 1)} ms  ({shift:+5.1f}%)"
              f"   wire +{tag['package_bytes'] - plain['package_bytes']:4d} B"
              f"   membership {render(row['membership_prove'], 2)}/"
              f"{render(row['membership_verify'], 2)} ms"
              f" once, {row['membership_bytes']} B")
        print(f"           indistinguishable across assets: {row['indistinguishable']}"
              f"   attacks rejected: "
              f"{all(a['status'] == 'rejected' for a in row['attacks'].values())}")
    result["asset_hiding"] = hiding

    print("\nsplit rails: securities do not need the width cash needs")
    split = []
    for sec_bits, cash_bits in args.split:
        rows = []
        for _ in range(args.repeats):
            rows.append(split_settlement(group, sec_bits, cash_bits))
        split.append({"securities_bits": sec_bits, "cash_bits": cash_bits,
                      "build": summarise(r[0] for r in rows),
                      "settle": summarise(r[1] for r in rows),
                      "package_bytes": exact(rows[-1][2])})
        row = split[-1]
        print(f"  sec {sec_bits:2d} / cash {cash_bits:2d}   build {render(row['build'], 1)}"
              f"  settle {render(row['settle'], 1)} ms"
              f"   package {row['package_bytes']['exact']:6d} B")
    result["split_rails"] = split

    print("\nnode verification throughput across worker processes (proving excluded)")
    parallel = []
    for workers in args.workers:
        rates = []
        for _ in range(args.parallel_repeats):
            with multiprocessing.Manager() as manager:
                barrier = manager.Barrier(workers)
                jobs = [(40, args.parallel_each, barrier)] * workers
                with ProcessPoolExecutor(max_workers=workers) as pool:
                    elapsed = list(pool.map(_verify_job, jobs))
            rates.append(workers * args.parallel_each / max(elapsed))
        done = workers * args.parallel_each
        throughput = summarise(rates)
        parallel.append({"workers": workers, "settlements_per_trial": done,
                         "per_second": throughput})
        print(f"  {workers:3d} workers  {render(throughput, 2, '/s')}")
    result["parallel"] = parallel

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2))
    print(f"\nwrote {args.out}")
    return 0


def _wire_size(group, obj) -> int:
    return package_bytes(group, obj)


def package_bytes(group, package) -> int:
    """Everything a counterparty has to send the settlement layer.

    Counted under a canonical encoding rather than by pickling: 32 bytes for a
    compressed group element, 32 for a scalar, actual length for a byte string.
    That is what a deployed wire format would cost, and it keeps the number
    comparable with the transport frames measured elsewhere.
    """
    return _wire_size(group, package)


def _wire_size(group, obj) -> int:
    if dataclasses.is_dataclass(obj):
        return sum(_wire_size(group, getattr(obj, f.name))
                   for f in dataclasses.fields(obj))
    if isinstance(obj, (list, tuple)):
        return sum(_wire_size(group, item) for item in obj)
    if isinstance(obj, dict):
        return sum(_wire_size(group, k) + _wire_size(group, v)
                   for k, v in obj.items())
    if isinstance(obj, bytes):
        return len(obj) if len(obj) != 32 else 32
    if isinstance(obj, bool):
        return 1
    if isinstance(obj, int):
        return 32                      # a field scalar
    if isinstance(obj, str):
        return len(obj.encode())
    return 32                          # a group element in this backend


if __name__ == "__main__":
    raise SystemExit(main())
