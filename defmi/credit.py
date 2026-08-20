"""Intraday credit and the default waterfall, with the numbers still closed.

Two things a real financial market infrastructure does that a plain netting cycle
does not.

It extends **intraday credit** against pledged collateral, which is what lets a
participant pay before it has been paid. The Bank of Japan's intraday overdraft
is the model: eligible collateral is pledged, an overdraft limit is granted
against it after a haircut, the overdraft is drawn, and the payment goes out ---
and for the participant these are one event, not four, because any of them
failing must undo the rest.

And it carries a **default waterfall** for the case the credit is not repaid.
Tranches are consumed in a fixed order --- the defaulter's own collateral, its
contribution to the fund, the infrastructure's own capital, then the surviving
members' contributions --- and the order is the whole point of the arrangement,
so it has to be enforced rather than assumed.

Both are stated over commitments. A net debit cap is committed rather than
published, which does more than hide its size: a coverage proof then shows only
that position plus cap lies in range, and says nothing about whether the position
itself was above or below zero. The sign disappears for free, and the offset
trick that hiding a signed position would otherwise need is not required
anywhere.

Waterfall ordering is enforced by a product: tranche k may be drawn only if
tranche k-1 is exhausted, which is exactly draw_k * remaining_{k-1} = 0. Both
factors stay committed, and the product commitment is the identity, so the
verifier has nothing to be told and nothing to check beyond the proof itself.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Sequence

from zk.commit import (
    OpeningProof, Pedersen, ProductProof, RangeProof, prove_bounded,
    prove_opening, prove_product, prove_range, verify_bounded, verify_opening,
    verify_product, verify_range,
)
from zk.groups import Group

CREDIT_DOMAIN = b"QOMM:DEFMI:CREDIT:v1"
WATERFALL_DOMAIN = b"QOMM:DEFMI:WATERFALL:v1"
MAX_CREDIT = (1 << 40) - 1


class CreditRefused(Exception):
    """A limit the pledged collateral does not support."""


class WaterfallExhausted(Exception):
    """A shortfall the tranches cannot absorb."""


@dataclass(frozen=True)
class CreditLine:
    """A net debit cap, committed, and the collateral standing behind it.

    ``haircut_bp`` is public because it is a published policy of the
    infrastructure. The collateral and the cap are not: what the proof
    establishes is that one covers the other, which is the only relation anyone
    outside the participant needs.

    The collateral figure here is already valued in the units of the cap. Turning
    a pledged security into a valued amount is the same product relation the cash
    leg of a settlement uses --- quantity times price, against a price the quorum
    signed --- and we have not built that step, so a deployment would need it
    before the collateral could be a different asset from the credit.
    """

    handle: bytes
    rail: str                     # which rail the cap relaxes; a cap is not portable
    cap_commitment: Any
    collateral_commitment: Any
    haircut_bp: int
    backing: RangeProof
    granted_at: int

    def digest(self, group: Group) -> bytes:
        digest = hashlib.sha256(CREDIT_DOMAIN)
        digest.update(len(self.handle).to_bytes(4, "big"))
        digest.update(self.handle)
        digest.update(len(self.rail).to_bytes(4, "big"))
        digest.update(self.rail.encode())
        digest.update(group.encode(self.cap_commitment))
        digest.update(group.encode(self.collateral_commitment))
        digest.update(self.haircut_bp.to_bytes(4, "big"))
        digest.update(self.granted_at.to_bytes(8, "big"))
        return digest.digest()


def _backing_bits(max_credit: int) -> int:
    return (10_000 * max_credit).bit_length()


def haircut_value(collateral: int, haircut_bp: int) -> int:
    """What a lender will lend against, in basis points of haircut."""
    return collateral * (10_000 - haircut_bp) // 10_000


def grant_credit(key: Pedersen, *, handle: bytes, rail: str, cap: int,
                 cap_blinding: int,
                 # ``key`` must be the key the rail's positions live under. A cap
                 # is denominated in the same units as the position it relaxes,
                 # so committing it under a different generator would make the
                 # two incomparable --- and the arithmetic would still typecheck.
                 collateral: int, collateral_blinding: int, haircut_bp: int,
                 granted_at: int, max_credit: int = MAX_CREDIT,
                 context: bytes = CREDIT_DOMAIN) -> CreditLine:
    """Run where the collateral openings are known --- by the pledging member.

    The infrastructure verifies rather than computes: it never sees the
    collateral, only that the cap it is being asked to underwrite is covered.
    """
    group = key.group
    lendable = haircut_value(collateral, haircut_bp)
    if lendable - cap < 0:
        raise CreditRefused(
            f"collateral supports {lendable} after a {haircut_bp}bp haircut, "
            f"which does not cover a cap of {cap}")
    # (10000 - h) * collateral / 10000 - cap >= 0, stated on the scaled values so
    # the integer division does not have to be proved
    scale = 10_000 - haircut_bp
    slack = scale * collateral - 10_000 * cap
    slack_blinding = (scale * collateral_blinding
                      - 10_000 * cap_blinding) % group.order
    # Stated on the scaled values --- 10000*collateral*(1-h) against 10000*cap ---
    # so the integer division in haircut_value never has to be proved. The width
    # grows by the fourteen bits of the scale factor, which is paid once when the
    # line is granted rather than once per order.
    backing = prove_range(key, key.commit(slack, slack_blinding), slack,
                          slack_blinding, _backing_bits(max_credit),
                          context + b":backing")
    return CreditLine(handle, rail, key.commit(cap, cap_blinding),
                      key.commit(collateral, collateral_blinding),
                      haircut_bp, backing, granted_at)


def check_credit(key: Pedersen, line: CreditLine, *, max_credit: int = MAX_CREDIT,
                 context: bytes = CREDIT_DOMAIN) -> tuple[bool, str]:
    """The infrastructure underwriting a limit it cannot see."""
    group = key.group
    if not 0 <= line.haircut_bp < 10_000:
        return False, "the haircut is not a fraction"
    scale = 10_000 - line.haircut_bp
    slack = group.mul(group.point_pow(line.collateral_commitment, scale),
                      group.neg(group.point_pow(line.cap_commitment, 10_000)))
    if not verify_range(key, slack, line.backing,
                        context + b":backing"):
        return False, "the pledged collateral does not cover the cap"
    return True, "ok"


# --- the default waterfall ------------------------------------------------

@dataclass(frozen=True)
class Tranche:
    """One layer of the waterfall, as a committed balance."""

    name: str
    commitment: Any


@dataclass(frozen=True)
class Draw:
    """What one tranche contributes, and the proof it was its turn.

    ``ordering`` is absent on the first tranche, which has nothing above it.
    Elsewhere it proves draw * remaining-above = 0: either nothing was taken
    here, or the layer above was already empty.
    """

    tranche: int
    amount_commitment: Any
    within: RangeProof
    ordering: ProductProof | None = None


@dataclass(frozen=True)
class Resolution:
    """A shortfall absorbed, layer by layer."""

    shortfall_commitment: Any
    shortfall_range: RangeProof
    draws: tuple
    balance: OpeningProof


class DefaultWaterfall:
    """Tranches consumed in a fixed order, with the order enforced."""

    def __init__(self, group: Group, key: Pedersen, tranches: Sequence[Tranche],
                 max_value: int = MAX_CREDIT):
        if not tranches:
            raise ValueError("a waterfall needs at least one tranche")
        self.group = group
        self.key = key
        self.tranches = list(tranches)
        self.max_value = max_value

    def build(self, *, shortfall: int, shortfall_blinding: int,
              balances: Sequence[int], blindings: Sequence[int],
              context: bytes = WATERFALL_DOMAIN) -> tuple[Resolution, list[int]]:
        """Run where every tranche opening is known --- by the infrastructure.

        Returns the resolution and the amounts drawn, so the tranches can be
        written down afterwards by whoever holds them.
        """
        group = self.group
        key = self.key
        order = group.order
        if shortfall < 0:
            raise ValueError("a shortfall is not negative")
        if len(balances) != len(self.tranches) or len(blindings) != len(self.tranches):
            raise ValueError("one balance and one blinding per tranche")
        if shortfall > sum(balances):
            raise WaterfallExhausted(
                f"a shortfall of {shortfall} exceeds the {sum(balances)} the "
                "waterfall holds")

        amounts, remaining = [], shortfall
        for balance in balances:
            take = min(balance, remaining)
            amounts.append(take)
            remaining -= take

        draw_blindings = [key.random_blinding() for _ in amounts]
        # the last one absorbs the sum so the balance proof closes exactly
        total = sum(draw_blindings[:-1]) % order
        draw_blindings[-1] = (shortfall_blinding - total) % order

        draws, above_value, above_blinding = [], None, None
        for index, (amount, blinding) in enumerate(zip(amounts, draw_blindings)):
            _, within, _ = prove_bounded(
                key, balances[index] - amount,
                (blindings[index] - blinding) % order, 0, self.max_value,
                context + b":within:" + index.to_bytes(2, "big"))
            ordering = None
            if index:
                # draw_k * remaining_{k-1} == 0, with the product commitment left
                # as the identity so the verifier has nothing to be handed
                ordering = prove_product(
                    key, key.commit(above_value, above_blinding),
                    above_value, above_blinding, amount, blinding, 0,
                    context + b":order:" + index.to_bytes(2, "big"))
            draws.append(Draw(index, key.commit(amount, blinding), within, ordering))
            above_value = balances[index] - amount
            above_blinding = (blindings[index] - blinding) % order

        residual = key.commit(shortfall, shortfall_blinding)
        for draw in draws:
            residual = group.mul(residual, group.neg(draw.amount_commitment))
        balance_proof = prove_opening(key, residual, 0, 0, context + b":balance")
        _, shortfall_range, _ = prove_bounded(
            key, shortfall, shortfall_blinding, 0, self.max_value,
            context + b":shortfall")
        return Resolution(key.commit(shortfall, shortfall_blinding),
                          shortfall_range, tuple(draws), balance_proof), amounts

    def check(self, resolution: Resolution,
              context: bytes = WATERFALL_DOMAIN) -> tuple[bool, str]:
        group = self.group
        key = self.key
        if len(resolution.draws) != len(self.tranches):
            return False, "one draw per tranche, present or zero"
        if not verify_bounded(key, resolution.shortfall_commitment,
                              resolution.shortfall_range, 0, self.max_value,
                              context + b":shortfall"):
            return False, "the shortfall is not shown to be a positive amount"

        above = None
        for index, draw in enumerate(resolution.draws):
            if draw.tranche != index:
                return False, "the draws are not in tranche order"
            remaining = group.mul(self.tranches[index].commitment,
                                  group.neg(draw.amount_commitment))
            if not verify_bounded(key, remaining, draw.within, 0, self.max_value,
                                  context + b":within:" + index.to_bytes(2, "big")):
                return False, f"tranche {self.tranches[index].name} is overdrawn"
            if index:
                if draw.ordering is None:
                    return False, "a draw out of the first tranche without an order proof"
                if not verify_product(key, above, draw.amount_commitment,
                                      group.identity(), draw.ordering,
                                      context + b":order:" + index.to_bytes(2, "big")):
                    return False, (f"tranche {self.tranches[index].name} was drawn "
                                   "before the one above it was exhausted")
            above = remaining

        residual = resolution.shortfall_commitment
        for draw in resolution.draws:
            residual = group.mul(residual, group.neg(draw.amount_commitment))
        if not verify_opening(key, residual, resolution.balance,
                              context + b":balance"):
            return False, "the draws do not add up to the shortfall"
        return True, "ok"

    def applied(self, resolution: Resolution) -> list[Tranche]:
        """The tranches after the resolution, still committed."""
        group = self.group
        return [Tranche(tranche.name,
                        group.mul(tranche.commitment, group.neg(draw.amount_commitment)))
                for tranche, draw in zip(self.tranches, resolution.draws)]
