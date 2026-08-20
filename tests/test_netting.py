"""Netting cycles, and the trade each mode actually makes.

The cost tests live in the measurement script. What matters here is behaviour,
and the behaviour that separates the modes is admissibility: a gross rail refuses
an order it cannot cover right now, a net rail waits until the close. The pair of
tests around that distinction is the point of the file.
"""

from __future__ import annotations

import random
import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from defmi.assets import AssetRegistry                                   # noqa: E402
from defmi.netting import (                                              # noqa: E402
    BatchAttestation, Coverage, NettingCycle, NettingMode, Order, Rejected,
)
from zk.commit import Pedersen, prove_product                            # noqa: E402
from zk.groups import make_group                                         # noqa: E402
from zk.zkpi import InstructionIssuer, SettlementVenue                   # noqa: E402

SEC_OPENING, CASH_OPENING = 10_000, 100_000_000
CTX = b"QOMM:DEFMI:CYCLE:v1"


@pytest.fixture(scope="module")
def group():
    return make_group("ed25519")


class Holder:
    """What a participant remembers; the cycle never sees any of it."""

    def __init__(self, key, handle, securities, cash):
        self.handle = handle
        self.securities = [securities, key.random_blinding()]
        self.cash = [cash, key.random_blinding()]


def make_cycle(group, mode, participants=3, *, attest=False,
               securities=SEC_OPENING, cash=CASH_OPENING, openings=None):
    """``openings`` gives per-participant securities, since a position and its
    opening have to be set together --- setting one afterwards is how a test
    breaks conservation and blames the code."""
    key = Pedersen(group, b"qomm:defmi:v1")
    registry = AssetRegistry(group, key, 16)
    sec_tag, sec_gamma = registry.blind(3)
    cash_tag, cash_gamma = registry.blind(0)
    # One quorum, dealt once, and a venue that trusts exactly it.
    issuer = InstructionIssuer(group, key, quorum_secret=key.random_blinding(),
                               quorum_blinding=key.random_blinding())
    cycle = NettingCycle(group, key, mode, sec_tag, sec_gamma, cash_tag, cash_gamma,
                         venue=SettlementVenue(group, key,
                                               quorum_key=issuer.quorum_key),
                         attest_batch=attest)
    holders = {}
    for i in range(participants):
        handle = f"p{i}".encode()
        holder = Holder(key, handle, (openings or {}).get(handle, securities), cash)
        holders[handle] = holder
        cycle.securities.open(handle, cycle.securities.tagged.commit(*holder.securities))
        cycle.cash.open(handle, cycle.cash.tagged.commit(*holder.cash))
    return key, issuer, cycle, holders


def make_order(group, key, issuer, cycle, holders, seller, buyer, quantity, price):
    """Built by the counterparties; raises Rejected if a gross rail is short."""
    value = quantity * price
    instruction, aux = issuer.issue(
        asset=3, amount=quantity, price=price,
        payer_handle=group.hash_to_point(buyer), payee_handle=group.hash_to_point(seller),
        deadline=1_500, nonce=secrets.token_bytes(32), quote_key=1_599_845,
        nodes=list(range(1, 8)), threshold=2, quorum=[1, 2, 3])
    cash_blinding = key.random_blinding()
    cash_reference = key.commit(value, cash_blinding)
    value_proof = prove_product(
        key, instruction.price_commitment, price, aux["blindings"]["price"],
        quantity, aux["blindings"]["amount"], cash_blinding, CTX + b":value")
    sold, bought = holders[seller], holders[buyer]
    sec_blinding = key.random_blinding()
    sec_leg = cycle.securities.build_leg(
        seller, buyer, quantity, sec_blinding, sold.securities[0], sold.securities[1],
        instruction.amount_commitment, aux["blindings"]["amount"], CTX + b":sec")
    value_blinding = key.random_blinding()
    cash_leg = cycle.cash.build_leg(
        buyer, seller, value, value_blinding, bought.cash[0], bought.cash[1],
        cash_reference, cash_blinding, CTX + b":cash")
    order = Order(instruction, sec_leg, cash_leg, cash_reference, value_proof)
    return order, (sec_blinding, value_blinding, quantity, value)


def apply_books(group, holders, seller, buyer, secrets_):
    sec_blinding, value_blinding, quantity, value = secrets_
    order = group.order
    sold, bought = holders[seller], holders[buyer]
    sold.securities[0] -= quantity
    sold.securities[1] = (sold.securities[1] - sec_blinding) % order
    bought.securities[0] += quantity
    bought.securities[1] = (bought.securities[1] + sec_blinding) % order
    bought.cash[0] -= value
    bought.cash[1] = (bought.cash[1] - value_blinding) % order
    sold.cash[0] += value
    sold.cash[1] = (sold.cash[1] + value_blinding) % order


def close_cycle(cycle, holders, *, now=1_100, attest=False, corrupt=False):
    coverages = {}
    for name, book, field in (("securities", cycle.securities, "securities"),
                              ("cash", cycle.cash, "cash")):
        if not book.net:
            continue
        coverages[name] = [
            book.build_coverage(handle, getattr(holder, field)[0],
                                getattr(holder, field)[1], CTX + b":" + name.encode())
            for handle, holder in holders.items()]
    attestation = None
    if attest:
        digest = cycle.batch_digest()
        if corrupt:
            digest = bytes(32)
        attestation = BatchAttestation(digest, b"", (1, 2, 3))
    return cycle.close(coverages, now=now, attestation=attestation)


# --- all four arms work ---------------------------------------------------

@pytest.mark.parametrize("mode,attest", [
    (NettingMode.GROSS_GROSS, False),
    (NettingMode.GROSS_NET, False),
    (NettingMode.NET_NET, False),
    (NettingMode.NET_NET, True),
])
def test_a_cycle_settles_and_conserves(group, mode, attest):
    key, issuer, cycle, holders = make_cycle(group, mode, 4, attest=attest)
    rng = random.Random(3)
    handles = list(holders)
    for _ in range(6):
        seller, buyer = rng.sample(handles, 2)
        order, secrets_ = make_order(group, key, issuer, cycle, holders,
                                     seller, buyer, 40, 100_000)
        accepted, reason = cycle.admit(order, now=1_000)
        assert accepted, reason
        apply_books(group, holders, seller, buyer, secrets_)
    receipt = close_cycle(cycle, holders, attest=attest)
    assert receipt.status == "closed", receipt.reason
    assert receipt.admitted == 6
    assert cycle.securities.conserved() and cycle.cash.conserved()


# --- the distinction that matters ----------------------------------------

def test_a_gross_rail_refuses_a_delivery_it_cannot_cover_yet(group):
    """This is the trade: settlement cannot fail, but the order cannot exist."""
    key, issuer, cycle, holders = make_cycle(
        group, NettingMode.GROSS_GROSS, 3, securities=0,
        openings={b"p1": 500})
    with pytest.raises(Rejected, match="refused before it exists"):
        make_order(group, key, issuer, cycle, holders, b"p0", b"p2", 100, 100_000)


def test_a_net_rail_lets_the_offsetting_pair_through_in_either_order(group):
    """And this is what the trade buys back: order-insensitivity.

    p0 holds nothing, receives a hundred from p1 and delivers a hundred to p2.
    Net zero either way. On a gross rail the delivery-first ordering is refused;
    on a net rail both orderings settle, which is the liquidity benefit netting
    exists to provide.
    """
    for first_delivery in (True, False):
        key, issuer, cycle, holders = make_cycle(
            group, NettingMode.NET_NET, 3, securities=0, openings={b"p1": 500})
        pairs = [(b"p0", b"p2"), (b"p1", b"p0")]
        if not first_delivery:
            pairs.reverse()
        for seller, buyer in pairs:
            order, secrets_ = make_order(group, key, issuer, cycle, holders,
                                         seller, buyer, 100, 100_000)
            accepted, reason = cycle.admit(order, now=1_000)
            assert accepted, f"{seller!r}->{buyer!r}: {reason}"
            apply_books(group, holders, seller, buyer, secrets_)
        assert close_cycle(cycle, holders).status == "closed"


def test_a_net_rail_fails_at_the_close_if_a_net_is_short(group):
    """The risk a net rail takes on, in the place it belongs."""
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3,
                                             securities=0, openings={b"p1": 500})
    order, secrets_ = make_order(group, key, issuer, cycle, holders,
                                 b"p0", b"p2", 100, 100_000)
    assert cycle.admit(order, now=1_000)[0]        # admitted with p0 at zero
    apply_books(group, holders, b"p0", b"p2", secrets_)
    assert holders[b"p0"].securities[0] < 0
    with pytest.raises(Rejected, match="short of its 0 cap"):
        close_cycle(cycle, holders)


# --- what a cycle refuses -------------------------------------------------

def test_cash_that_is_not_quantity_times_price_is_refused(group):
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3)
    order, _ = make_order(group, key, issuer, cycle, holders, b"p0", b"p1",
                          40, 100_000)
    wrong = Order(order.instruction, order.securities, order.cash,
                  key.commit(1, key.random_blinding()), order.value_proof)
    accepted, reason = cycle.admit(wrong, now=1_000)
    assert not accepted and "quantity times price" in reason


def test_a_leg_cannot_pay_itself(group):
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3)
    order, _ = make_order(group, key, issuer, cycle, holders, b"p0", b"p1",
                          40, 100_000)
    from defmi.netting import Leg
    same = Leg(b"p0", b"p0", order.securities.delta,
               order.securities.delta_link, order.securities.cover)
    accepted, reason = cycle.admit(
        Order(order.instruction, same, order.cash, order.cash_reference,
              order.value_proof), now=1_000)
    assert not accepted and "pay itself" in reason


def test_an_instruction_settles_once_per_cycle(group):
    key, issuer, cycle, holders = make_cycle(group, NettingMode.GROSS_GROSS, 3)
    order, secrets_ = make_order(group, key, issuer, cycle, holders, b"p0", b"p1",
                                 40, 100_000)
    assert cycle.admit(order, now=1_000)[0]
    apply_books(group, holders, b"p0", b"p1", secrets_)
    accepted, reason = cycle.admit(order, now=1_000)
    assert not accepted and "already settled" in reason


def test_a_net_rail_must_not_carry_per_order_cover_proofs(group):
    """Belt and braces: the mode decides, not the submitter."""
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3)
    order, _ = make_order(group, key, issuer, cycle, holders, b"p0", b"p1",
                          40, 100_000)
    gross_key, gross_issuer, gross_cycle, gross_holders = make_cycle(
        group, NettingMode.GROSS_GROSS, 3)
    covered, _ = make_order(group, gross_key, gross_issuer, gross_cycle,
                            gross_holders, b"p0", b"p1", 40, 100_000)
    from defmi.netting import Leg
    smuggled = Leg(order.securities.payer, order.securities.payee,
                   order.securities.delta, order.securities.delta_link,
                   covered.securities.cover)
    accepted, reason = cycle.admit(
        Order(order.instruction, smuggled, order.cash, order.cash_reference,
              order.value_proof), now=1_000)
    assert not accepted and "must not carry" in reason


def test_a_cycle_that_loses_value_does_not_close(group):
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3)
    order, secrets_ = make_order(group, key, issuer, cycle, holders, b"p0", b"p1",
                                 40, 100_000)
    assert cycle.admit(order, now=1_000)[0]
    apply_books(group, holders, b"p0", b"p1", secrets_)
    # a position quietly inflated after admission
    position = cycle.securities.positions[b"p1"]
    position.commitment = group.mul(position.commitment,
                                    cycle.securities.tagged.commit(5, 0))
    assert not cycle.securities.conserved()
    holders[b"p1"].securities[0] += 5
    receipt = close_cycle(cycle, holders)
    assert receipt.status == "failed" and "conserve" in receipt.reason


# --- the attested variant -------------------------------------------------

def test_an_attestation_for_other_positions_is_refused(group):
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3,
                                             attest=True)
    order, secrets_ = make_order(group, key, issuer, cycle, holders, b"p0", b"p1",
                                 40, 100_000)
    assert cycle.admit(order, now=1_000)[0]
    apply_books(group, holders, b"p0", b"p1", secrets_)
    receipt = close_cycle(cycle, holders, attest=True, corrupt=True)
    assert receipt.status == "failed" and "other positions" in receipt.reason


def test_an_attested_cycle_needs_an_attestation(group):
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3,
                                             attest=True)
    receipt = close_cycle(cycle, holders, attest=False)
    assert receipt.status == "failed" and "needs an attestation" in receipt.reason


def test_a_batch_attestation_only_makes_sense_when_both_rails_net(group):
    key = Pedersen(group, b"qomm:defmi:v1")
    registry = AssetRegistry(group, key, 16)
    sec_tag, sec_gamma = registry.blind(3)
    cash_tag, cash_gamma = registry.blind(0)
    for mode in (NettingMode.GROSS_GROSS, NettingMode.GROSS_NET):
        with pytest.raises(ValueError, match="both rails are netted"):
            NettingCycle(group, key, mode, sec_tag, sec_gamma, cash_tag, cash_gamma,
                         attest_batch=True)


# --- what a cycle reveals -------------------------------------------------

def test_positions_are_commitments_not_amounts(group):
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3)
    order, secrets_ = make_order(group, key, issuer, cycle, holders, b"p0", b"p1",
                                 40, 100_000)
    assert cycle.admit(order, now=1_000)[0]
    apply_books(group, holders, b"p0", b"p1", secrets_)
    encoded = b"".join(group.encode(cycle.securities.balance(h)) for h in holders)
    encoded += b"".join(group.encode(cycle.cash.balance(h)) for h in holders)
    for secret in (40, SEC_OPENING, SEC_OPENING - 40, 4_000_000):
        assert secret.to_bytes(4, "big") not in encoded


# --- net debit caps -------------------------------------------------------

def _grant(group, key, cycle, handle, cap, collateral, haircut_bp=500, book="cash"):
    from defmi.credit import grant_credit
    target = cycle.cash if book == "cash" else cycle.securities
    cap_blinding = key.random_blinding()
    line = grant_credit(target.tagged, handle=handle, rail=book, cap=cap,
                        cap_blinding=cap_blinding,
                        collateral=collateral,
                        collateral_blinding=key.random_blinding(),
                        haircut_bp=haircut_bp, granted_at=1_000)
    accepted, reason = target.grant(line)
    return line, cap_blinding, accepted, reason


def test_a_cap_lets_a_net_position_go_below_zero_and_no_further(group):
    """The infrastructure names how much risk it will carry, and carries it."""
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3,
                                             securities=0, openings={b"p1": 5_000})
    cap = 300
    line, cap_blinding, accepted, reason = _grant(
        group, key, cycle, b"p0", cap, 10_000, book="securities")
    assert accepted, reason
    order, secrets_ = make_order(group, key, issuer, cycle, holders, b"p0", b"p2",
                                 200, 100_000)
    assert cycle.admit(order, now=1_000)[0]
    apply_books(group, holders, b"p0", b"p2", secrets_)
    assert holders[b"p0"].securities[0] == -200        # net short, within the cap

    coverages = {"securities": [
        cycle.securities.build_coverage(
            h, holders[h].securities[0], holders[h].securities[1],
            CTX + b":securities",
            cap_value=cap if h == b"p0" else 0,
            cap_blinding=cap_blinding if h == b"p0" else 0)
        for h in holders],
        "cash": [cycle.cash.build_coverage(h, holders[h].cash[0], holders[h].cash[1],
                                           CTX + b":cash") for h in holders]}
    receipt = cycle.close(coverages, now=1_100)
    assert receipt.status == "closed", receipt.reason


def test_a_position_beyond_its_cap_still_fails(group):
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3,
                                             securities=0, openings={b"p1": 5_000})
    line, cap_blinding, accepted, _ = _grant(
        group, key, cycle, b"p0", 300, 10_000, book="securities")
    assert accepted
    order, secrets_ = make_order(group, key, issuer, cycle, holders, b"p0", b"p2",
                                 400, 100_000)
    assert cycle.admit(order, now=1_000)[0]
    apply_books(group, holders, b"p0", b"p2", secrets_)
    with pytest.raises(Rejected, match="short of its 300 cap"):
        cycle.securities.build_coverage(
            b"p0", holders[b"p0"].securities[0], holders[b"p0"].securities[1],
            CTX + b":securities", cap_value=300, cap_blinding=cap_blinding)


def test_a_cap_the_collateral_does_not_support_is_refused(group):
    from defmi.credit import CreditRefused, grant_credit
    key = Pedersen(group, b"qomm:defmi:v1")
    with pytest.raises(CreditRefused, match="does not cover a cap"):
        grant_credit(key, handle=b"p0", rail="cash", cap=10_000,
                     cap_blinding=key.random_blinding(),
                     collateral=10_000, collateral_blinding=key.random_blinding(),
                     haircut_bp=500, granted_at=1_000)


def test_a_cap_hides_which_side_of_zero_the_position_is_on(group):
    """A coverage proof speaks about position plus cap, so the sign is not in it."""
    key = Pedersen(group, b"qomm:defmi:v1")
    registry = AssetRegistry(group, key, 16)
    tag, gamma = registry.blind(3)
    from defmi.netting import PositionBook
    shapes = set()
    for value in (-250, 250):
        book = PositionBook(group, key, tag, gamma, net=True, rail="securities")
        blinding = key.random_blinding()
        book.open(b"p0", book.tagged.commit(value, blinding))
        cap_blinding = key.random_blinding()
        from defmi.credit import grant_credit
        line = grant_credit(book.tagged, handle=b"p0", rail="securities", cap=300,
                            cap_blinding=cap_blinding,
                            collateral=10_000,
                            collateral_blinding=key.random_blinding(),
                            haircut_bp=500, granted_at=1_000)
        assert book.grant(line)[0]
        coverage = book.build_coverage(b"p0", value, blinding, CTX,
                                       cap_value=300, cap_blinding=cap_blinding)
        assert book.check_coverage(coverage, CTX)[0]
        shapes.add((len(coverage.proof.bit_commitments), coverage.proof.bits))
    assert len(shapes) == 1, f"the sign shows in the proof shape: {shapes}"


# --- pledge, underwrite, draw and pay as one event ------------------------

def test_the_four_steps_happen_together_or_not_at_all(group):
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3,
                                             securities=0, openings={b"p1": 5_000})
    from defmi.credit import grant_credit
    cap_blinding = key.random_blinding()
    line = grant_credit(cycle.securities.tagged, handle=b"p0", rail="securities",
                        cap=300, cap_blinding=cap_blinding,
                        collateral=10_000, collateral_blinding=key.random_blinding(),
                        haircut_bp=500, granted_at=1_000)
    order, secrets_ = make_order(group, key, issuer, cycle, holders, b"p0", b"p2",
                                 200, 100_000)
    accepted, reason = cycle.admit_with_credit(order, line=line, now=1_000)
    assert accepted, reason
    assert cycle.granted == [line]
    apply_books(group, holders, b"p0", b"p2", secrets_)


def test_a_failed_payment_unwinds_the_grant(group):
    """Otherwise a refused order would leave a limit standing behind nothing."""
    key, issuer, cycle, holders = make_cycle(group, NettingMode.NET_NET, 3)
    from defmi.credit import grant_credit
    line = grant_credit(cycle.cash.tagged, handle=b"p0", rail="cash", cap=300,
                        cap_blinding=key.random_blinding(), collateral=10_000,
                        collateral_blinding=key.random_blinding(),
                        haircut_bp=500, granted_at=1_000)
    order, _ = make_order(group, key, issuer, cycle, holders, b"p0", b"p1",
                          40, 100_000)
    broken = Order(order.instruction, order.securities, order.cash,
                   key.commit(1, key.random_blinding()), order.value_proof)
    accepted, reason = cycle.admit_with_credit(broken, line=line, now=1_000)
    assert not accepted
    assert b"p0" not in cycle.cash.credit and cycle.granted == []


# --- the waterfall --------------------------------------------------------

def _waterfall(group, key, balances):
    from defmi.credit import DefaultWaterfall, Tranche
    names = ["defaulter collateral", "defaulter fund share", "FMI capital",
             "surviving members"]
    blindings = [key.random_blinding() for _ in balances]
    tranches = [Tranche(n, key.commit(b, r))
                for n, b, r in zip(names, balances, blindings)]
    return DefaultWaterfall(group, key, tranches), blindings


@pytest.mark.parametrize("shortfall,expected", [
    (250, [250, 0, 0, 0]),
    (700, [300, 200, 200, 0]),
    (1_200, [300, 200, 500, 200]),
])
def test_the_waterfall_consumes_tranches_in_order(group, shortfall, expected):
    key = Pedersen(group, b"qomm:defmi:v1")
    balances = [300, 200, 500, 5_000]
    waterfall, blindings = _waterfall(group, key, balances)
    resolution, amounts = waterfall.build(
        shortfall=shortfall, shortfall_blinding=key.random_blinding(),
        balances=balances, blindings=blindings)
    assert amounts == expected
    accepted, reason = waterfall.check(resolution)
    assert accepted, reason


def test_a_shortfall_larger_than_the_waterfall_is_refused(group):
    from defmi.credit import WaterfallExhausted
    key = Pedersen(group, b"qomm:defmi:v1")
    balances = [300, 200, 500, 5_000]
    waterfall, blindings = _waterfall(group, key, balances)
    with pytest.raises(WaterfallExhausted, match="exceeds the 6000"):
        waterfall.build(shortfall=99_999, shortfall_blinding=key.random_blinding(),
                        balances=balances, blindings=blindings)


def test_skipping_a_tranche_is_caught_by_the_ordering_proof(group):
    """The real attack: draw from below while the layer above still has money."""
    from defmi.credit import Draw
    key = Pedersen(group, b"qomm:defmi:v1")
    balances = [300, 200, 500, 5_000]
    waterfall, blindings = _waterfall(group, key, balances)
    # honest resolution for 200, which should come entirely from tranche 0
    honest, amounts = waterfall.build(
        shortfall=200, shortfall_blinding=key.random_blinding(),
        balances=balances, blindings=blindings)
    assert amounts == [200, 0, 0, 0]
    # now try to take it from tranche 1 instead, leaving tranche 0 untouched
    shortfall_blinding = key.random_blinding()
    draw_blinding = shortfall_blinding
    zero = key.random_blinding()
    from zk.commit import prove_bounded, prove_opening, prove_product
    order = group.order
    draws = []
    for index, (balance, blinding) in enumerate(zip(balances, blindings)):
        amount = 200 if index == 1 else 0
        amount_blinding = draw_blinding if index == 1 else 0
        _, within, _ = prove_bounded(
            key, balance - amount, (blinding - amount_blinding) % order,
            0, waterfall.max_value,
            b"QOMM:DEFMI:WATERFALL:v1:within:" + index.to_bytes(2, "big"))
        ordering = None
        if index:
            above_value = balances[index - 1] - (200 if index - 1 == 1 else 0)
            above_blinding = blindings[index - 1]
            ordering = prove_product(
                key, key.commit(above_value, above_blinding), above_value,
                above_blinding, amount, amount_blinding, 0,
                b"QOMM:DEFMI:WATERFALL:v1:order:" + index.to_bytes(2, "big"))
        draws.append(Draw(index, key.commit(amount, amount_blinding), within, ordering))
    residual = key.commit(200, shortfall_blinding)
    for draw in draws:
        residual = group.mul(residual, group.neg(draw.amount_commitment))
    balance_proof = prove_opening(key, residual, 0, 0,
                                  b"QOMM:DEFMI:WATERFALL:v1:balance")
    _, shortfall_range, _ = prove_bounded(
        key, 200, shortfall_blinding, 0, waterfall.max_value,
        b"QOMM:DEFMI:WATERFALL:v1:shortfall")
    forged = type(honest)(key.commit(200, shortfall_blinding), shortfall_range,
                          tuple(draws), balance_proof)
    accepted, reason = waterfall.check(forged)
    assert not accepted and "before the one above it was exhausted" in reason


def test_the_tranches_after_a_resolution_are_still_commitments(group):
    key = Pedersen(group, b"qomm:defmi:v1")
    balances = [300, 200, 500, 5_000]
    waterfall, blindings = _waterfall(group, key, balances)
    resolution, amounts = waterfall.build(
        shortfall=700, shortfall_blinding=key.random_blinding(),
        balances=balances, blindings=blindings)
    after = waterfall.applied(resolution)
    # the draw blindings stay with whoever built the resolution, so the invariant
    # to check is the homomorphic one rather than a reconstruction
    for tranche, before, draw in zip(after, waterfall.tranches, resolution.draws):
        assert group.encode(tranche.commitment) == group.encode(
            group.mul(before.commitment, group.neg(draw.amount_commitment)))
    assert sum(amounts) == 700
