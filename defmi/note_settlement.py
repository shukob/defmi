"""Delivery versus payment where neither side has an account.

The account version of this settles between four named handles. That is the last
thing in the design that says who is trading, so this version replaces both rails
with note ledgers: each leg spends a note into a payee note and a change note,
and says which note it spent only to the extent of naming a ring.

The binding to the instruction survives the change with one extra proof per leg.
A note ledger states its value commitments against a blinded asset tag, while the
quorum issued the instruction against the base generator before any tag existed,
so the two are compared by a cross-generator equality proof rather than by
subtraction. Everything else --- the product relation for cash, the two-leg
atomicity, the nullifier --- is unchanged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from zk.commit import (
    CrossGeneratorProof, Pedersen, ProductProof, prove_product, prove_same_value,
    verify_product, verify_same_value,
)
from zk.groups import Group
from zk.zkpi import SettlementVenue, ZkPaymentInstruction

from .notes import Note, NoteLedger, SpendProof

NOTE_SETTLE_DOMAIN = b"QOMM:DEFMI:NOTE-DVP:v1"


@dataclass(frozen=True)
class NoteLeg:
    """One rail's half of a settlement: a ring, a spend, and the notes it makes.

    The payee's note is first by convention. Nothing in the proof distinguishes
    it, so a verifier that took them in the other order would be checking the
    change against the instruction --- hence the convention is enforced, not
    assumed.
    """

    ring: tuple
    spend: SpendProof
    notes: tuple


@dataclass(frozen=True)
class NoteDvpPackage:
    instruction: ZkPaymentInstruction
    securities: NoteLeg
    cash: NoteLeg
    quantity_link: CrossGeneratorProof
    cash_value_commitment: Any
    cash_link: CrossGeneratorProof
    value_proof: ProductProof


@dataclass(frozen=True)
class NoteReceipt:
    nullifier: str
    status: str
    reason: str
    securities_before: str
    securities_after: str
    cash_before: str
    cash_after: str
    settled_at: int
    signature: str

    def digest(self) -> bytes:
        parts = (self.nullifier, self.status, self.reason, self.securities_before,
                 self.securities_after, self.cash_before, self.cash_after,
                 str(self.settled_at))
        digest = hashlib.sha256(NOTE_SETTLE_DOMAIN)
        for part in parts:
            encoded = part.encode()
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
        return digest.digest()


def build_note_package(group: Group, key: Pedersen, *,
                       instruction: ZkPaymentInstruction,
                       securities: NoteLedger, cash: NoteLedger,
                       securities_ring: Sequence[int], securities_index: int,
                       securities_opening, securities_tag, securities_gamma: int,
                       cash_ring: Sequence[int], cash_index: int,
                       cash_opening, cash_tag, cash_gamma: int,
                       buyer_securities_address, seller_securities_address,
                       seller_cash_address, buyer_cash_address,
                       quantity: int, price: int,
                       instruction_amount_blinding: int,
                       instruction_price_blinding: int,
                       context: bytes = NOTE_SETTLE_DOMAIN) -> NoteDvpPackage:
    """Assembled by the counterparties, who hold the note openings."""
    value = quantity * price
    sec_spend, sec_notes, sec_openings = securities.build_spend(
        securities_ring, securities_index, securities_opening,
        securities_tag, securities_gamma,
        [(buyer_securities_address, quantity),
         (seller_securities_address, securities_opening.value - quantity)],
        context + b":sec")
    cash_spend, cash_notes, cash_openings = cash.build_spend(
        cash_ring, cash_index, cash_opening, cash_tag, cash_gamma,
        [(seller_cash_address, value),
         (buyer_cash_address, cash_opening.value - value)],
        context + b":cash")

    # the payee's securities note has to carry the instructed quantity. Its
    # commitment lives under the tag, the instruction's under the base point.
    sec_tagged = securities_tag.key_for(key)
    quantity_link = prove_same_value(
        key, sec_tagged.g, key.g, sec_spend.outputs[0],
        instruction.amount_commitment, quantity,
        _tagged_blinding(group, sec_openings[0], securities_gamma, quantity),
        instruction_amount_blinding, context + b":qty-link")

    # the cash the seller receives, restated under the base point so the product
    # relation can be checked against the instruction alone
    cash_tagged = cash_tag.key_for(key)
    cash_blinding = key.random_blinding()
    cash_value_commitment = key.commit(value, cash_blinding)
    cash_link = prove_same_value(
        key, cash_tagged.g, key.g, cash_spend.outputs[0], cash_value_commitment,
        value, _tagged_blinding(group, cash_openings[0], cash_gamma, value),
        cash_blinding, context + b":cash-link")

    value_proof = prove_product(
        key, instruction.price_commitment, price, instruction_price_blinding,
        quantity, instruction_amount_blinding, cash_blinding,
        context + b":value")

    return NoteDvpPackage(
        instruction=instruction,
        securities=NoteLeg(tuple(securities_ring), sec_spend, tuple(sec_notes)),
        cash=NoteLeg(tuple(cash_ring), cash_spend, tuple(cash_notes)),
        quantity_link=quantity_link,
        cash_value_commitment=cash_value_commitment,
        cash_link=cash_link,
        value_proof=value_proof)


def _tagged_blinding(group: Group, opening, gamma: int, value: int) -> int:
    """An output's blinding against the tag, not against the bare generator.

    ``build_spend`` hands back the bare-generator blinding because that is what
    the payee needs; the tagged one is gamma*value smaller.
    """
    return (opening.blinding - gamma * value) % group.order


class NoteDefmi:
    """Two note rails with two-leg finality, blind to what and to whom."""

    def __init__(self, group: Group, key: Pedersen | None = None,
                 signing_key: Ed25519PrivateKey | None = None,
                 venue: SettlementVenue | None = None,
                 max_value: int | None = None):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:defmi:v1")
        kwargs = {} if max_value is None else {"max_value": max_value}
        self.securities = NoteLedger(group, self.key, **kwargs)
        self.cash = NoteLedger(group, self.key, **kwargs)
        self._signing_key = signing_key or Ed25519PrivateKey.generate()
        self.public_key = self._signing_key.public_key()
        self.venue = venue or SettlementVenue(group, self.key)
        if group.encode(self.key.h) != group.encode(self.venue.key.h):
            raise ValueError(
                "the instruction venue and the ledgers use different commitment "
                "keys; bindings between them would be meaningless")

    def _check(self, package: NoteDvpPackage, now: int,
               context: bytes) -> tuple[bool, str]:
        key = self.key
        instruction = package.instruction

        ok, reason = self.venue.verify(instruction, now=now)
        if not ok:
            return False, f"instruction: {reason}"

        ok, reason = self.securities.check_spend(
            package.securities.ring, package.securities.spend, context + b":sec")
        if not ok:
            return False, f"securities leg: {reason}"
        ok, reason = self.cash.check_spend(
            package.cash.ring, package.cash.spend, context + b":cash")
        if not ok:
            return False, f"cash leg: {reason}"

        for leg, label in ((package.securities, "securities"), (package.cash, "cash")):
            if len(leg.notes) != len(leg.spend.outputs):
                return False, f"{label} leg has a note without a commitment"
            for note, commitment in zip(leg.notes, leg.spend.outputs):
                # the note that lands in the pool must carry exactly the value
                # commitment the proof is about; otherwise a payer could prove it
                # paid the instructed quantity and then deposit something else
                if self.group.encode(note.value_commitment) != self.group.encode(commitment):
                    return False, f"{label} leg note does not carry its proved value"

        sec_generator = package.securities.spend.tag.point
        if not verify_same_value(key, sec_generator, key.g,
                                 package.securities.spend.outputs[0],
                                 instruction.amount_commitment,
                                 package.quantity_link, context + b":qty-link"):
            return False, "securities leg does not deliver the instructed quantity"

        cash_generator = package.cash.spend.tag.point
        if not verify_same_value(key, cash_generator, key.g,
                                 package.cash.spend.outputs[0],
                                 package.cash_value_commitment,
                                 package.cash_link, context + b":cash-link"):
            return False, "the cash leg does not match the value it claims"

        if not verify_product(key, instruction.price_commitment,
                              instruction.amount_commitment,
                              package.cash_value_commitment, package.value_proof,
                              context + b":value"):
            return False, "cash leg is not quantity times price"
        return True, "ok"

    def settle(self, package: NoteDvpPackage, *, now: int,
               context: bytes = NOTE_SETTLE_DOMAIN) -> NoteReceipt:
        before_securities = self.securities.snapshot().hex()
        before_cash = self.cash.snapshot().hex()
        ok, reason = self._check(package, now, context)

        if ok:
            # both legs are checked before either is applied
            self.securities.apply_spend(package.securities.spend,
                                        package.securities.notes)
            self.cash.apply_spend(package.cash.spend, package.cash.notes)
            spent, spend_reason = self.venue.settle(package.instruction, now=now)
            if not spent:                                   # pragma: no cover
                raise RuntimeError(f"venue refused after checks passed: {spend_reason}")

        receipt = NoteReceipt(
            nullifier=package.instruction.nullifier(self.group).hex(),
            status="settled" if ok else "rejected",
            reason=reason,
            securities_before=before_securities,
            securities_after=self.securities.snapshot().hex(),
            cash_before=before_cash,
            cash_after=self.cash.snapshot().hex(),
            settled_at=now, signature="")
        signature = self._signing_key.sign(receipt.digest()).hex()
        return NoteReceipt(**{**receipt.__dict__, "signature": signature})

    def verify_receipt(self, receipt: NoteReceipt,
                       public_key: Ed25519PublicKey | None = None) -> bool:
        key = public_key or self.public_key
        try:
            key.verify(bytes.fromhex(receipt.signature), receipt.digest())
        except (InvalidSignature, ValueError):
            return False
        return True
