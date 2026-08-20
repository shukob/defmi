"""Delivery versus payment, driven by a zkPI, over ledgers that cannot read themselves.

The division of labour is the design. DeFMI checks arithmetic it can verify on
its own --- nothing created, nothing negative, nothing settled twice, and the two
legs move together or not at all. It does *not* check that the price was right or
that the asset was the one asked for: that meaning was established by the
computing quorum and is carried by the signature on the instruction. Asking the
settlement layer to re-derive it would mean giving it the plaintext, which is the
one thing the whole construction exists to avoid.

What DeFMI does check about value, and can, is that the cash leg is consistent
with the securities leg:

    cash amount = quantity * price

which is a product relation over three commitments and therefore provable
without opening any of them.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping

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

from .ledger import ConfidentialLedger, TransferProof

SETTLE_DOMAIN = b"QOMM:DEFMI:DVP:v1"


@dataclass(frozen=True)
class DvpPackage:
    """Everything the two counterparties hand to DeFMI. No plaintext anywhere."""

    instruction: ZkPaymentInstruction
    securities_from: bytes
    securities_to: bytes
    cash_from: bytes
    cash_to: bytes
    securities_leg: TransferProof
    cash_leg: TransferProof
    value_proof: ProductProof          # cash = quantity * price
    quantity_link: CrossGeneratorProof        # securities leg moves the instructed quantity
    cash_commitment: Any               # commitment to quantity * price


@dataclass(frozen=True)
class SettlementReceipt:
    """The only thing DeFMI emits. Digests, a status, and a signature."""

    nullifier: str
    status: str
    reason: str
    securities_snapshot_before: str
    securities_snapshot_after: str
    cash_snapshot_before: str
    cash_snapshot_after: str
    settled_at: int
    signature: str

    def body(self) -> bytes:
        digest = hashlib.sha256(SETTLE_DOMAIN + b":receipt:")
        for part in (self.nullifier, self.status, self.reason,
                     self.securities_snapshot_before, self.securities_snapshot_after,
                     self.cash_snapshot_before, self.cash_snapshot_after):
            digest.update(len(part).to_bytes(4, "big"))
            digest.update(part.encode())
        digest.update(self.settled_at.to_bytes(8, "big"))
        return digest.digest()


def build_package(group: Group, key: Pedersen, *, instruction: ZkPaymentInstruction,
                  securities: ConfidentialLedger, cash: ConfidentialLedger,
                  securities_from: bytes, securities_to: bytes,
                  cash_from: bytes, cash_to: bytes,
                  quantity: int, price: int,
                  seller_securities_balance: int, seller_securities_blinding: int,
                  buyer_cash_balance: int, buyer_cash_blinding: int,
                  instruction_amount_blinding: int,
                  instruction_price_blinding: int,
                  securities_tag=None, securities_gamma: int = 0,
                  context: bytes = SETTLE_DOMAIN) -> tuple[DvpPackage, "PayerCarry"]:
    """Assembled by the counterparties, who are the only ones holding the openings.

    Returns the package that goes to DeFMI and, separately, the openings the
    counterparties have to keep. The split is deliberate: a party that loses its
    blindings can no longer prove anything about its own balance, so carrying
    them forward is part of holding an account, not part of the protocol
    message.
    """
    securities_leg, securities_secrets = securities.build_transfer(
        seller_securities_balance, seller_securities_blinding, quantity,
        context + b":sec", tag=securities_tag, gamma=securities_gamma,
        amount_bounded=True)
    value = quantity * price
    # both amounts are pinned by the instruction --- the quantity through the
    # link below, the cash through the product relation --- so neither needs a
    # second range proof here. That is half the range proofs in the package.
    cash_leg, cash_secrets = cash.build_transfer(
        buyer_cash_balance, buyer_cash_blinding, value, context + b":cash",
        amount_bounded=True)

    # The securities leg must move exactly the quantity the instruction commits
    # to. The two commitments sit under different value generators whenever the
    # leg carries an asset tag, and the same proof covers the untagged case, so
    # the wire format does not advertise which one is in use.
    leg_generator = key.g if securities_tag is None else securities_tag.point
    quantity_link = prove_same_value(
        key, leg_generator, key.g,
        securities_leg.amount_commitment, instruction.amount_commitment,
        quantity, securities_secrets.amount_blinding, instruction_amount_blinding,
        context + b":qty-link")

    # and the cash leg must be that quantity times the instructed price. The
    # quantity is taken from the instruction rather than from the leg: the link
    # above already ties them, and the instruction is the thing the quorum
    # signed.
    value_proof = prove_product(
        key, instruction.price_commitment, price, instruction_price_blinding,
        quantity, instruction_amount_blinding, cash_secrets.amount_blinding,
        context + b":value")

    package = DvpPackage(
        instruction=instruction,
        securities_from=securities_from, securities_to=securities_to,
        cash_from=cash_from, cash_to=cash_to,
        securities_leg=securities_leg, cash_leg=cash_leg,
        value_proof=value_proof, quantity_link=quantity_link,
        cash_commitment=cash_leg.amount_commitment)
    carry = PayerCarry(
        securities_balance=seller_securities_balance - quantity,
        securities_blinding=securities_secrets.remainder_blinding,
        cash_balance=buyer_cash_balance - value,
        cash_blinding=cash_secrets.remainder_blinding,
        quantity_blinding=securities_secrets.payee_delta,
        cash_amount_blinding=cash_secrets.payee_delta)
    return package, carry


@dataclass(frozen=True)
class PayerCarry:
    """What each payer must remember once the package settles.

    A Pedersen balance is only usable by whoever knows its blinding, so this is
    the account itself as far as the holder is concerned. The payees need the
    amount blindings for the same reason.
    """

    securities_balance: int
    securities_blinding: int
    cash_balance: int
    cash_blinding: int
    quantity_blinding: int
    cash_amount_blinding: int


class Defmi:
    """Asset and cash rails with two-leg finality, blind to what they settle."""

    def __init__(self, group: Group, key: Pedersen | None = None,
                 signing_key: Ed25519PrivateKey | None = None,
                 venue: SettlementVenue | None = None):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:defmi:v1")
        self.securities = ConfidentialLedger(group, self.key)
        self.cash = ConfidentialLedger(group, self.key)
        self._signing_key = signing_key or Ed25519PrivateKey.generate()
        self.public_key = self._signing_key.public_key()
        self.venue = venue or SettlementVenue(group, self.key)
        # The instruction and the ledgers have to share a commitment key. With
        # different second generators the two sets of commitments are simply
        # incomparable, so every binding between an instruction and a ledger
        # movement would be vacuous while still type-checking.
        if group.encode(self.key.h) != group.encode(self.venue.key.h):
            raise ValueError(
                "the instruction venue and the ledgers use different commitment "
                "keys; bindings between them would be meaningless")
        self.receipts: list[SettlementReceipt] = []

    # --- checks DeFMI can make on its own -------------------------------
    def _check(self, package: DvpPackage, now: int,
               context: bytes) -> tuple[bool, str]:
        group = self.group
        key = self.key
        instruction = package.instruction

        ok, reason = self.venue.verify(instruction, now=now)
        if not ok:
            return False, f"instruction: {reason}"

        for handle, ledger, label in (
                (package.securities_from, self.securities, "securities payer"),
                (package.securities_to, self.securities, "securities payee"),
                (package.cash_from, self.cash, "cash payer"),
                (package.cash_to, self.cash, "cash payee")):
            if handle not in ledger._accounts:
                return False, f"{label} account is not open"
        if package.securities_from == package.securities_to:
            return False, "securities legs share a handle"
        if package.cash_from == package.cash_to:
            return False, "cash legs share a handle"

        ok, reason = self.securities.check_transfer(
            package.securities_from, package.securities_leg, context + b":sec",
            amount_bounded=True)
        if not ok:
            return False, f"securities leg: {reason}"
        ok, reason = self.cash.check_transfer(
            package.cash_from, package.cash_leg, context + b":cash",
            amount_bounded=True)
        if not ok:
            return False, f"cash leg: {reason}"

        tag = package.securities_leg.tag
        leg_generator = key.g if tag is None else tag.point
        if not verify_same_value(key, leg_generator, key.g,
                                 package.securities_leg.amount_commitment,
                                 instruction.amount_commitment,
                                 package.quantity_link, context + b":qty-link"):
            return False, "securities leg does not move the instructed quantity"

        if not verify_product(key, instruction.price_commitment,
                              instruction.amount_commitment,
                              package.cash_commitment, package.value_proof,
                              context + b":value"):
            return False, "cash leg is not quantity times price"
        if group.encode(package.cash_commitment) != group.encode(
                package.cash_leg.amount_commitment):
            return False, "cash leg moves a different amount than it proves"
        return True, "ok"

    # --- settlement -----------------------------------------------------
    def settle(self, package: DvpPackage, *, now: int,
               context: bytes = SETTLE_DOMAIN) -> SettlementReceipt:
        before_securities = self.securities.snapshot().hex()
        before_cash = self.cash.snapshot().hex()
        ok, reason = self._check(package, now, context)

        if ok:
            # both legs are checked before either is applied, so a failure on the
            # second leg cannot leave the first one settled
            self.securities.apply_transfer(package.securities_from,
                                           package.securities_to,
                                           package.securities_leg)
            self.cash.apply_transfer(package.cash_from, package.cash_to,
                                     package.cash_leg)
            spent, spend_reason = self.venue.settle(package.instruction, now=now)
            if not spent:                                   # pragma: no cover
                raise RuntimeError(f"venue refused after checks passed: {spend_reason}")

        receipt = SettlementReceipt(
            nullifier=package.instruction.nullifier(self.group).hex(),
            status="settled" if ok else "rejected",
            reason=reason,
            securities_snapshot_before=before_securities,
            securities_snapshot_after=self.securities.snapshot().hex(),
            cash_snapshot_before=before_cash,
            cash_snapshot_after=self.cash.snapshot().hex(),
            settled_at=now, signature="")
        signed = SettlementReceipt(
            **{**receipt.__dict__,
               "signature": self._signing_key.sign(receipt.body()).hex()})
        self.receipts.append(signed)
        return signed

    def verify_receipt(self, receipt: SettlementReceipt,
                       issuer: Ed25519PublicKey | None = None) -> bool:
        issuer = issuer or self.public_key
        try:
            issuer.verify(bytes.fromhex(receipt.signature), receipt.body())
            return True
        except (InvalidSignature, ValueError):
            return False

    def solvent(self) -> bool:
        """Both rails still hold exactly what was issued into them."""
        return self.securities.conserved() and self.cash.conserved()
