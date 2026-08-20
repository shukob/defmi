"""Delivery versus payment with no accounts on either side.

The account version of these tests checks that value cannot be created and that
the legs move together. Those still matter, but the new question is whether the
binding to the instruction survives the move to notes: the quantity now lives in
a commitment under a per-spend tag, while the instruction committed to it under
the base generator before any tag existed.
"""

from __future__ import annotations

import random
import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from defmi.assets import AssetRegistry                                  # noqa: E402
from defmi.note_settlement import NoteDefmi, build_note_package         # noqa: E402
from defmi.notes import Wallet                                          # noqa: E402
from zk.commit import Pedersen                                          # noqa: E402
from zk.groups import make_group                                        # noqa: E402
from zk.zkpi import InstructionIssuer, SettlementVenue                  # noqa: E402

QTY, PRICE, RING = 100, 99_990, 8
SEC_BALANCE, CASH_BALANCE = 5_000, 50_000_000


@pytest.fixture(scope="module")
def group():
    return make_group("ed25519")


@pytest.fixture()
def venue(group):
    key = Pedersen(group, b"qomm:defmi:v1")
    registry = AssetRegistry(group, key, 16)
    defmi = NoteDefmi(group, key, venue=SettlementVenue(group, key))
    issuer = InstructionIssuer(group, key)
    sec_key = key.with_value_generator(registry.tags[3])
    cash_key = key.with_value_generator(registry.tags[0])
    seller, buyer = Wallet(group), Wallet(group)
    for i in range(RING):
        owner = seller.address if i == 0 else Wallet(group).address
        note, _, _ = defmi.securities.build_note(owner, SEC_BALANCE, sec_key)
        defmi.securities.add(note)
        owner = buyer.address if i == 0 else Wallet(group).address
        note, _, _ = defmi.cash.build_note(owner, CASH_BALANCE, cash_key)
        defmi.cash.add(note)
    return {"key": key, "registry": registry, "defmi": defmi, "issuer": issuer,
            "sec_key": sec_key, "cash_key": cash_key,
            "seller": seller, "buyer": buyer}


def _package(group, v, *, quantity=QTY, price=PRICE, sec_asset=3, seed=4):
    defmi, key, registry = v["defmi"], v["key"], v["registry"]
    sec_found = defmi.securities.scan(v["seller"], v["sec_key"])
    cash_found = defmi.cash.scan(v["buyer"], v["cash_key"])
    si, ci = next(iter(sec_found)), next(iter(cash_found))
    instruction, aux = v["issuer"].issue(
        asset=3, amount=QTY, price=PRICE,
        payer_handle=group.hash_to_point(b"entity-buyer"),
        payee_handle=group.hash_to_point(b"entity-seller"),
        deadline=1_500, nonce=secrets.token_bytes(32), quote_key=1_599_845,
        nodes=list(range(1, 8)), threshold=2, quorum=[1, 2, 3])
    sec_tag, sec_gamma = registry.blind(sec_asset)
    cash_tag, cash_gamma = registry.blind(0)
    rng = random.Random(seed)
    return build_note_package(
        group, key, instruction=instruction,
        securities=defmi.securities, cash=defmi.cash,
        securities_ring=defmi.securities.ring_for(si, RING, rng),
        securities_index=si, securities_opening=sec_found[si],
        securities_tag=sec_tag, securities_gamma=sec_gamma,
        cash_ring=defmi.cash.ring_for(ci, RING, rng), cash_index=ci,
        cash_opening=cash_found[ci], cash_tag=cash_tag, cash_gamma=cash_gamma,
        buyer_securities_address=v["buyer"].address,
        seller_securities_address=v["seller"].address,
        seller_cash_address=v["seller"].address,
        buyer_cash_address=v["buyer"].address,
        quantity=quantity, price=price,
        instruction_amount_blinding=aux["blindings"]["amount"],
        instruction_price_blinding=aux["blindings"]["price"])


def test_a_valid_settlement_delivers_both_sides(group, venue):
    defmi = venue["defmi"]
    receipt = defmi.settle(_package(group, venue), now=1_000)
    assert receipt.status == "settled", receipt.reason
    assert defmi.verify_receipt(receipt)
    got = defmi.securities.scan(venue["buyer"], venue["sec_key"])
    assert QTY in [o.value for o in got.values()]
    paid = defmi.cash.scan(venue["seller"], venue["cash_key"])
    assert QTY * PRICE in [o.value for o in paid.values()]


def test_the_ledgers_never_name_a_counterparty(group, venue):
    """The whole reason for the rewrite: nothing in the package is an address."""
    defmi = venue["defmi"]
    package = _package(group, venue)
    assert defmi.settle(package, now=1_000).status == "settled"
    for wallet in (venue["seller"], venue["buyer"]):
        for point in (wallet.address.view, wallet.address.spend):
            encoded = group.encode(point)
            assert encoded not in _bytes_of(group, package)


def _bytes_of(group, obj) -> bytes:
    import dataclasses as dc
    if obj is None:
        return b""
    if dc.is_dataclass(obj):
        return b"".join(_bytes_of(group, getattr(obj, f.name)) for f in dc.fields(obj))
    if isinstance(obj, (list, tuple)):
        return b"".join(_bytes_of(group, item) for item in obj)
    if isinstance(obj, dict):
        return b"".join(_bytes_of(group, k) + _bytes_of(group, val)
                        for k, val in obj.items())
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, bool):
        return b""
    if isinstance(obj, int):
        return obj.to_bytes(32, "big", signed=False) if obj >= 0 else b""
    if isinstance(obj, str):
        return obj.encode()
    try:
        return group.encode(obj)
    except Exception:
        return b""


def test_delivering_the_wrong_quantity_is_rejected(group, venue):
    defmi = venue["defmi"]
    receipt = defmi.settle(_package(group, venue, quantity=QTY + 1), now=1_000)
    assert receipt.status == "rejected"
    assert "instructed quantity" in receipt.reason


def test_paying_the_wrong_amount_is_rejected(group, venue):
    defmi = venue["defmi"]
    receipt = defmi.settle(_package(group, venue, price=PRICE - 10), now=1_000)
    assert receipt.status == "rejected"
    assert "quantity times price" in receipt.reason


def test_nothing_moves_when_a_leg_fails(group, venue):
    defmi = venue["defmi"]
    before_sec = defmi.securities.snapshot()
    before_cash = defmi.cash.snapshot()
    assert defmi.settle(_package(group, venue, price=PRICE + 5),
                        now=1_000).status == "rejected"
    assert defmi.securities.snapshot() == before_sec
    assert defmi.cash.snapshot() == before_cash


def test_an_instruction_settles_once(group, venue):
    defmi = venue["defmi"]
    package = _package(group, venue)
    assert defmi.settle(package, now=1_000).status == "settled"
    replay = defmi.settle(package, now=1_000)
    # the instruction nullifier catches it before the serial does; either is a
    # correct refusal, and asserting on one of them in particular would only
    # pin the order the checks happen to run in
    assert replay.status == "rejected"
    assert "already settled" in replay.reason or "already spent" in replay.reason


def test_an_expired_instruction_does_not_settle(group, venue):
    receipt = venue["defmi"].settle(_package(group, venue), now=2_000)
    assert receipt.status == "rejected" and "deadline" in receipt.reason


def test_a_note_that_does_not_carry_its_proved_value_is_refused(group, venue):
    """Otherwise a payer could prove one delivery and deposit another."""
    defmi, key = venue["defmi"], venue["key"]
    package = _package(group, venue)
    good = package.securities.notes[0]
    swapped = type(good)(good.one_time, key.commit(1, key.random_blinding()),
                         good.ephemeral, good.masked_value, good.masked_blinding)
    leg = type(package.securities)(package.securities.ring, package.securities.spend,
                                   (swapped,) + package.securities.notes[1:])
    tampered = type(package)(**{**package.__dict__, "securities": leg})
    receipt = defmi.settle(tampered, now=1_000)
    assert receipt.status == "rejected" and "proved value" in receipt.reason


def test_receipts_are_signed_and_tamper_evident(group, venue):
    defmi = venue["defmi"]
    receipt = defmi.settle(_package(group, venue), now=1_000)
    assert defmi.verify_receipt(receipt)
    forged = type(receipt)(**{**receipt.__dict__, "status": "rejected"})
    assert not defmi.verify_receipt(forged)
