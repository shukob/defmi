"""Netting cycles: gross-gross, gross-net, net-net, without reading anything.

The three shapes are the BIS delivery-versus-payment models --- model 1 settles
both legs trade by trade, model 2 settles securities gross and cash net, model 3
nets both. Here the choice is not only a settlement-system question: it decides
how many range proofs exist and when, which is the one cost in this design that
hurts.

A rail is either gross or net, and that single distinction carries everything.

A **gross** rail checks each order as it arrives. The participant proves that its
position after the order is still non-negative, so an order that would leave it
short is refused before it exists and settlement failure cannot happen. The price
is that admission is order-sensitive: a participant due to receive a hundred and
deliver a hundred is refused if the delivery arrives first, which is exactly the
liquidity benefit netting exists to provide, given up on purpose.

A **net** rail accumulates. Positions move homomorphically with no proof at all,
and because a commitment hides a value's sign as readily as its magnitude, an
intermediate position may be negative without anything leaking --- nothing is
proved about it, so nothing about it is disclosed. One range proof per
participant at the close establishes that the *net* is covered. That restores the
liquidity benefit and makes admission order-insensitive, at the cost of a cycle
that can fail at the close, which is the classic risk stated in its usual place.

Neither arrangement needs the offset trick that hiding a signed position would
otherwise require: on a gross rail nothing is ever negative, and on a net rail
nothing intermediate is ever proved.

There is a second, larger knob, and measuring the first one is what exposed it.
Netting the rails saves only the per-order cover proof, because every order still
carries an instruction the settlement layer has to verify, and that verification
--- which contains its own range proofs on amount and price --- does not net.
What does net is the *instruction*. A cycle can be run against one quorum
attestation over the closing positions instead of one instruction per trade, and
then the settlement layer's work stops depending on the number of trades at all.
The saving is real but it is not free: with a batch attestation the layer no
longer checks the individual trades, so the split between participants is
attested by the quorum rather than verified. Conservation and solvency still hold
outright, and each participant can still check its own net, so what is given up
is third-party verifiability of the split --- the same bargain a central
counterparty represents, made explicit.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any

from zk.commit import (
    CrossGeneratorProof, Pedersen, ProductProof, RangeProof, prove_bounded,
    prove_product, prove_range, prove_same_value, verify_bounded, verify_product,
    verify_range, verify_same_value,
)
from .credit import CreditLine, check_credit
from zk.groups import Group
from zk.zkpi import SettlementVenue, ZkPaymentInstruction

CYCLE_DOMAIN = b"QOMM:DEFMI:CYCLE:v1"
MAX_POSITION = (1 << 40) - 1


class NettingMode(Enum):
    """Which rails defer their coverage check to the close of the cycle."""

    GROSS_GROSS = "gross-gross"      # BIS DVP model 1
    GROSS_NET = "gross-net"          # model 2: securities gross, cash net
    NET_NET = "net-net"              # model 3

    @property
    def securities_net(self) -> bool:
        return self is NettingMode.NET_NET

    @property
    def cash_net(self) -> bool:
        return self is not NettingMode.GROSS_GROSS


class Rejected(Exception):
    """An order that would leave a gross position short."""


@dataclass
class Position:
    handle: bytes
    commitment: Any
    opening_commitment: Any
    moves: int = 0


@dataclass(frozen=True)
class Leg:
    """One rail's movement: one delta, one payer, one payee.

    Deliberately not a pair of independent debit and credit records. With one
    delta there is no way for the two sides to disagree, so conservation on the
    rail holds by construction rather than by a check that could be forgotten.

    ``cover`` is present only on a gross rail. The payer's new position is never
    sent: the book derives it as old/delta, a group operation, and checks the
    proof against what it derived.
    """

    payer: bytes
    payee: bytes
    delta: Any
    delta_link: CrossGeneratorProof
    cover: RangeProof | None = None


@dataclass(frozen=True)
class Order:
    """One trade's effect on four positions.

    ``cash_reference`` is a commitment to quantity times price under the base
    generator, with ``value_proof`` relating it to the quantity and price the
    quorum signed. The instruction commits to the factors, never to the product,
    so without it the cash leg would have nothing to be checked against.
    """

    instruction: ZkPaymentInstruction
    securities: Leg
    cash: Leg
    cash_reference: Any
    value_proof: ProductProof


@dataclass(frozen=True)
class BatchAttestation:
    """The quorum standing behind a whole cycle instead of each trade in it.

    Signed over the closing position commitments, so it says nothing about any
    individual trade and cannot be replayed onto a different set of positions.
    """

    digest: bytes
    signature: bytes
    quorum: tuple


@dataclass(frozen=True)
class Coverage:
    """A participant showing, at the close, that its net is covered."""

    handle: bytes
    proof: RangeProof


@dataclass(frozen=True)
class CycleReceipt:
    mode: str
    admitted: int
    refused: int
    status: str
    reason: str
    securities_before: str
    securities_after: str
    cash_before: str
    cash_after: str
    closed_at: int


class PositionBook:
    """Positions on one rail, under a tag that is stable for the cycle.

    Stability is required for positions to accumulate at all; the tag is
    refreshed when the cycle rolls, so what a reader can group together is
    confined to one cycle rather than following an asset.
    """

    def __init__(self, group: Group, key: Pedersen, tag, gamma: int, *,
                 net: bool, rail: str = "", max_position: int = MAX_POSITION):
        self.group = group
        self.key = key
        self.tag = tag
        self.gamma = gamma
        self.tagged = tag.key_for(key)
        self.net = net
        self.rail = rail
        self.max_position = max_position
        self.positions: dict[bytes, Position] = {}
        self.credit: dict[bytes, CreditLine] = {}

    def open(self, handle: bytes, commitment) -> Position:
        if handle in self.positions:
            raise ValueError("position already open")
        self.positions[handle] = Position(handle, commitment, commitment)
        return self.positions[handle]

    def balance(self, handle: bytes):
        return self.positions[handle].commitment

    # --- how far below zero a position may go ----------------------------
    def grant(self, line: CreditLine) -> tuple[bool, str]:
        """Underwrite a net debit cap the infrastructure cannot see.

        The cap is committed, not published. That hides its size, and it also
        removes the sign: a coverage proof afterwards shows only that position
        plus cap is in range, never which side of zero the position was on.
        """
        if line.handle not in self.positions:
            return False, "unknown position handle"
        if line.rail != self.rail:
            return False, f"a cap for {line.rail!r} does not relax {self.rail!r}"
        # checked under the credit module's own domain, not the cycle's: a line
        # has to verify the same way outside the cycle that granted it, and
        # under the rail's own key, since that is what the cap is denominated in
        ok, reason = check_credit(self.tagged, line)
        if not ok:
            return False, reason
        self.credit[line.handle] = line
        return True, "ok"

    def _cap_commitment(self, handle: bytes):
        """A participant with no line has a cap of zero, which is the identity."""
        line = self.credit.get(handle)
        return line.cap_commitment if line else self.group.identity()

    def _headroom(self, commitment, handle: bytes):
        """position + cap, which is what has to be non-negative."""
        return self.group.mul(commitment, self._cap_commitment(handle))

    # --- building a move -------------------------------------------------
    def build_leg(self, payer: bytes, payee: bytes, amount: int, blinding: int,
                  position_value: int, position_blinding: int,
                  reference_commitment, reference_blinding: int,
                  context: bytes, cap_value: int = 0,
                  cap_blinding: int = 0) -> Leg:
        """Run by the payer, the only party that knows its position."""
        delta = self.tagged.commit(amount, blinding)
        delta_link = prove_same_value(
            self.key, self.tagged.g, self.key.g, delta, reference_commitment,
            amount, blinding, reference_blinding, context + b":link")
        cover = None
        if not self.net:
            headroom = position_value - amount + cap_value
            if headroom < 0:
                raise Rejected(
                    f"position {position_value} and a cap of {cap_value} cannot "
                    f"cover {amount}; on a gross rail the order is refused "
                    "before it exists")
            cover = prove_range(
                self.tagged, self.tagged.commit(headroom, (
                    position_blinding - blinding + cap_blinding) % self.group.order),
                headroom,
                (position_blinding - blinding + cap_blinding) % self.group.order,
                self.max_position.bit_length(), context + b":cover")
        return Leg(payer, payee, delta, delta_link, cover)

    # --- checking one -----------------------------------------------------
    def check(self, leg: Leg, reference_commitment,
              context: bytes) -> tuple[bool, str]:
        group = self.group
        for handle in (leg.payer, leg.payee):
            if handle not in self.positions:
                return False, "unknown position handle"
        if leg.payer == leg.payee:
            return False, "a leg cannot pay itself"
        if not verify_same_value(self.key, self.tagged.g, self.key.g, leg.delta,
                                 reference_commitment, leg.delta_link,
                                 context + b":link"):
            return False, "the amount leaving does not match the instruction"
        if self.net:
            if leg.cover is not None:
                return False, "a net rail must not carry a per-order cover proof"
            return True, "ok"
        if leg.cover is None:
            return False, "a gross rail needs a cover proof on every leg"
        residual = group.mul(self.positions[leg.payer].commitment,
                             group.neg(leg.delta))
        if not verify_range(self.tagged, self._headroom(residual, leg.payer),
                            leg.cover, context + b":cover"):
            return False, "the order would leave the position short of its cap"
        return True, "ok"

    def apply(self, leg: Leg) -> None:
        group = self.group
        payer, payee = self.positions[leg.payer], self.positions[leg.payee]
        payer.commitment = group.mul(payer.commitment, group.neg(leg.delta))
        payee.commitment = group.mul(payee.commitment, leg.delta)
        payer.moves += 1
        payee.moves += 1

    # --- the close --------------------------------------------------------
    def build_coverage(self, handle: bytes, value: int, blinding: int,
                       context: bytes, cap_value: int = 0,
                       cap_blinding: int = 0) -> Coverage:
        headroom = value + cap_value
        if headroom < 0:
            raise Rejected(
                f"net position {value} is short of its {cap_value} cap at the "
                "close; the cycle goes to the waterfall")
        combined_blinding = (blinding + cap_blinding) % self.group.order
        proof = prove_range(
            self.tagged, self.tagged.commit(headroom, combined_blinding),
            headroom, combined_blinding, self.max_position.bit_length(),
            context + b":close")
        return Coverage(handle, proof)

    def check_coverage(self, coverage: Coverage,
                       context: bytes) -> tuple[bool, str]:
        if coverage.handle not in self.positions:
            return False, "unknown position handle"
        headroom = self._headroom(self.positions[coverage.handle].commitment,
                                  coverage.handle)
        if not verify_range(self.tagged, headroom, coverage.proof,
                            context + b":close"):
            return False, "net position is not covered, even against its cap"
        return True, "ok"

    # --- what the cycle checks for free -----------------------------------
    def conserved(self) -> bool:
        """No proof and no opening: the two products simply have to agree."""
        group = self.group
        total = opened = group.identity()
        for position in self.positions.values():
            total = group.mul(total, position.commitment)
            opened = group.mul(opened, position.opening_commitment)
        return group.encode(total) == group.encode(opened)

    def snapshot(self) -> bytes:
        digest = hashlib.sha256(CYCLE_DOMAIN + (b"net" if self.net else b"gross"))
        for handle in sorted(self.positions):
            digest.update(len(handle).to_bytes(4, "big"))
            digest.update(handle)
            digest.update(self.group.encode(self.positions[handle].commitment))
        return digest.digest()


class NettingCycle:
    """A batch of orders under one mode, all-or-nothing at the close."""

    def __init__(self, group: Group, key: Pedersen, mode: NettingMode,
                 securities_tag, securities_gamma: int,
                 cash_tag, cash_gamma: int,
                 venue: SettlementVenue | None = None,
                 max_position: int = MAX_POSITION,
                 attest_batch: bool = False):
        self.attest_batch = attest_batch
        if attest_batch and mode is not NettingMode.NET_NET:
            raise ValueError(
                "a batch attestation replaces the per-trade instruction, which "
                "only makes sense when both rails are netted")
        self.group = group
        self.key = key
        self.mode = mode
        self.venue = venue or SettlementVenue(group, key)
        if group.encode(key.h) != group.encode(self.venue.key.h):
            raise ValueError(
                "the instruction venue and the position books use different "
                "commitment keys; bindings between them would be meaningless")
        self.securities = PositionBook(group, key, securities_tag, securities_gamma,
                                       net=mode.securities_net, rail="securities",
                                       max_position=max_position)
        self.cash = PositionBook(group, key, cash_tag, cash_gamma,
                                 net=mode.cash_net, rail="cash",
                                 max_position=max_position)
        self.admitted: list[Order] = []
        self.granted: list[CreditLine] = []
        self.refused: list[str] = []
        self.closed = False

    def admit(self, order: Order, *, now: int,
              context: bytes = CYCLE_DOMAIN) -> tuple[bool, str]:
        """Verify and apply, or refuse and change nothing."""
        if self.closed:
            return False, "the cycle is closed"
        if self.attest_batch:
            return self._accumulate(order, context)
        ok, reason = self.venue.verify(order.instruction, now=now)
        if not ok:
            self.refused.append(reason)
            return False, f"instruction: {reason}"

        instruction = order.instruction
        if not verify_product(self.key, instruction.price_commitment,
                              instruction.amount_commitment, order.cash_reference,
                              order.value_proof, context + b":value"):
            self.refused.append("cash is not quantity times price")
            return False, "cash is not quantity times price"

        checks = (
            (self.securities, order.securities, instruction.amount_commitment,
             context + b":sec"),
            (self.cash, order.cash, order.cash_reference, context + b":cash"),
        )
        for book, leg, commitment, ctx in checks:
            ok, reason = book.check(leg, commitment, ctx)
            if not ok:
                self.refused.append(reason)
                return False, reason
        # every check passed, so nothing can fail half way through
        for book, leg, _, _ in checks:
            book.apply(leg)
        spent, reason = self.venue.settle(instruction, now=now)
        if not spent:
            self.refused.append(reason)
            return False, reason
        self.admitted.append(order)
        return True, "ok"

    def admit_with_credit(self, order: Order, *, line: CreditLine, now: int,
                          pledge: Leg | None = None, pledge_reference=None,
                          context: bytes = CYCLE_DOMAIN) -> tuple[bool, str]:
        """Pledge, underwrite, draw and pay as one event.

        A participant that needs the overdraft to make the payment cannot do
        these in sequence: a pledge that lands without the limit being granted
        has locked collateral for nothing, and a limit granted without the
        pledge is unsecured. So everything is checked first and applied only if
        all of it holds --- the pledge on the collateral rail, the limit against
        that pledge, and the payment the limit exists to permit.
        """
        if self.closed:
            return False, "the cycle is closed"

        if pledge is not None:
            if pledge_reference is None:
                return False, "a pledge without the commitment it is stated against"
            ok, reason = self.securities.check(pledge, pledge_reference,
                                               context + b":pledge")
            if not ok:
                return False, f"pledge: {reason}"

        books = {"securities": self.securities, "cash": self.cash}
        if line.rail not in books:
            return False, f"credit: unknown rail {line.rail!r}"
        book = books[line.rail]
        ok, reason = check_credit(book.tagged, line)
        if not ok:
            return False, f"credit: {reason}"

        # the limit has to be in place for the payment to be admissible, so it is
        # staged rather than applied: if the payment fails, the grant unwinds
        previous = book.credit.get(line.handle)
        book.credit[line.handle] = line
        if pledge is not None:
            self.securities.apply(pledge)
        accepted, why = self.admit(order, now=now, context=context)
        if not accepted:
            if previous is None:
                book.credit.pop(line.handle, None)
            else:
                book.credit[line.handle] = previous
            if pledge is not None:
                self.securities.apply(
                    Leg(pledge.payee, pledge.payer, pledge.delta,
                        pledge.delta_link, None))
            return False, why
        self.granted.append(line)
        return True, "ok"

    def _accumulate(self, order: Order, context: bytes) -> tuple[bool, str]:
        """Apply a leg without verifying it, because the batch will be attested.

        Handles and self-payment are still checked: they cost nothing and a
        malformed cycle is not something an attestation should be able to
        authorise.
        """
        for book, leg in ((self.securities, order.securities), (self.cash, order.cash)):
            for handle in (leg.payer, leg.payee):
                if handle not in book.positions:
                    return False, "unknown position handle"
            if leg.payer == leg.payee:
                return False, "a leg cannot pay itself"
        for book, leg in ((self.securities, order.securities), (self.cash, order.cash)):
            book.apply(leg)
        self.admitted.append(order)
        return True, "ok"

    def batch_digest(self) -> bytes:
        """What an attestation signs: the closing positions and nothing else."""
        digest = hashlib.sha256(CYCLE_DOMAIN + b":batch:" + self.mode.value.encode())
        digest.update(self.securities.snapshot())
        digest.update(self.cash.snapshot())
        digest.update(len(self.admitted).to_bytes(4, "big"))
        return digest.digest()

    def close(self, coverages: dict[str, list[Coverage]] | None = None, *,
              now: int, context: bytes = CYCLE_DOMAIN,
              attestation: BatchAttestation | None = None) -> CycleReceipt:
        """Check every net rail is covered, then make the cycle final."""
        before_sec = self.securities.snapshot().hex()
        before_cash = self.cash.snapshot().hex()
        coverages = coverages or {}
        status, reason = "closed", "ok"

        if self.attest_batch:
            if attestation is None:
                status, reason = "failed", "an attested cycle needs an attestation"
            elif attestation.digest != self.batch_digest():
                status, reason = "failed", "the attestation is for other positions"

        for name, book in (("securities", self.securities), ("cash", self.cash)):
            if not book.net:
                continue
            supplied = {c.handle for c in coverages.get(name, ())}
            if supplied != set(book.positions):
                status, reason = "failed", f"{name}: not every net position is covered"
                break
            for coverage in coverages[name]:
                ok, why = book.check_coverage(coverage, context + b":" + name.encode())
                if not ok:
                    status, reason = "failed", f"{name}: {why}"
                    break
            if status == "failed":
                break

        if status == "closed":
            if not (self.securities.conserved() and self.cash.conserved()):
                status, reason = "failed", "a rail does not conserve value"

        if status == "closed":
            self.closed = True
        return CycleReceipt(
            mode=self.mode.value, admitted=len(self.admitted),
            refused=len(self.refused), status=status, reason=reason,
            securities_before=before_sec,
            securities_after=self.securities.snapshot().hex(),
            cash_before=before_cash, cash_after=self.cash.snapshot().hex(),
            closed_at=now)
