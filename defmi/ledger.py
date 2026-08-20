"""A ledger whose balances are commitments, not numbers.

The point of hiding a request and then settling it in the clear is nothing, so
the settlement layer has to hold balances it cannot read. Pedersen commitments
give exactly the structure needed:

    transfer of a from A to B      B_A' = B_A / C_a ,  B_B' = B_B * C_a
    conservation                   the product of all balances is unchanged, by
                                   construction, with no proof required
    solvency                       proved per transfer: the amount is not
                                   negative and the payer's new balance is not
                                   negative

Accounts are opaque handles. The ledger never learns which legal entity or which
asset a handle stands for; that meaning is established elsewhere and attested by
the computing quorum. What the ledger enforces on its own is arithmetic:
nothing is created, nothing goes negative, and nothing settles twice.
"""

from __future__ import annotations

import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping

from zk.commit import Pedersen, RangeProof, prove_bounded, verify_bounded
from zk.groups import Group

LEDGER_DOMAIN = b"QOMM:DEFMI:LEDGER:v1"

# Balances live in a declared range. The width has to be fixed in advance
# because a range proof is only meaningful against a published bound.
MAX_BALANCE = (1 << 40) - 1


def _tagged_context(group, context: bytes, tag) -> bytes:
    """Bind the tag into the transcript.

    The prover picks the tag, so the generator the range proofs are stated
    against is prover-chosen. No attack follows --- the verification equations
    already pin it --- but a challenge that does not cover a value the prover
    controls is the kind of gap worth closing while it is one line.
    """
    if tag is None:
        return context
    return context + b":tag:" + group.encode(tag.point)


@dataclass(frozen=True)
class TransferSecrets:
    """The three blindings a transfer produces, which are not interchangeable.

    ``amount_blinding`` opens the amount commitment against the tag the leg was
    proved under; ``payee_delta`` is what the receiving account adds to its own
    blinding, which differs by gamma*amount once a tag is in play; and
    ``remainder_blinding`` is the payer's balance from here on. Returning them
    as one number is how a tagged leg silently stops verifying.
    """

    amount_blinding: int
    payee_delta: int
    remainder_blinding: int


@dataclass(frozen=True)
class TransferProof:
    """What a payer must show to move value it will not reveal."""

    amount_commitment: Any
    amount_range: RangeProof
    remainder_commitment: Any
    remainder_range: RangeProof
    tag: Any = None                      # the blinded asset tag, when there is one


@dataclass(frozen=True)
class LedgerEntry:
    handle: bytes
    balance: Any            # Pedersen commitment
    sequence: int


class InsufficientProof(ValueError):
    pass


class ConfidentialLedger:
    """Opaque handles to committed balances, with an auditable conservation check."""

    def __init__(self, group: Group, key: Pedersen | None = None,
                 max_balance: int = MAX_BALANCE,
                 issuer: Ed25519PublicKey | None = None):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:defmi:v1")
        self.max_balance = max_balance
        # Who is allowed to create balance. A ledger without one takes any
        # opening commitment as issued, which makes conservation a statement
        # about what was admitted rather than about what exists --- see
        # `open_account`.
        self.issuer = issuer
        self._accounts: dict[bytes, LedgerEntry] = {}
        self._minted = group.identity()      # running total of everything issued
        self._issued: set[bytes] = set()     # authorisations already used

    # --- issuance -------------------------------------------------------
    def issuance_body(self, handle: bytes, balance_commitment, nonce: bytes) -> bytes:
        """What an issuer signs to allow one opening balance to exist."""
        return hashlib.sha256(
            b"QOMM:DEFMI:ISSUE:v1"
            + len(handle).to_bytes(4, "big") + handle
            + self.group.encode(balance_commitment)
            + len(nonce).to_bytes(4, "big") + nonce).digest()

    def open_account(self, handle: bytes, balance_commitment,
                     authorisation: bytes | None = None,
                     nonce: bytes = b"") -> LedgerEntry:
        """Admit a balance, and say who was allowed to create it.

        This used to take any commitment and fold it straight into `minted`, so
        the conservation check said "nothing has been created or destroyed since
        the ledger accepted these" and not "only an issuer created anything".
        Anyone who could call this could mint. A ledger constructed with an
        issuer now requires that issuer's signature over the handle, the
        commitment and a nonce it has not seen before; one without an issuer
        still accepts anything and says so, because the test fixtures and the
        conservation measurements do not need an issuance model and should not
        pretend to have one.
        """
        if handle in self._accounts:
            raise ValueError("handle already open")
        if self.issuer is not None:
            if authorisation is None:
                raise InsufficientProof(
                    "this ledger has an issuer, so an opening balance needs its "
                    "authorisation")
            body = self.issuance_body(handle, balance_commitment, nonce)
            if body in self._issued:
                raise InsufficientProof("that issuance authorisation was already used")
            try:
                self.issuer.verify(authorisation, body)
            except InvalidSignature as bad:
                raise InsufficientProof(
                    "the opening balance is not signed by the issuer") from bad
            self._issued.add(body)
        entry = LedgerEntry(handle, balance_commitment, 0)
        self._accounts[handle] = entry
        self._minted = self.group.mul(self._minted, balance_commitment)
        return entry

    def balance(self, handle: bytes):
        return self._accounts[handle].balance

    def handles(self) -> tuple[bytes, ...]:
        return tuple(sorted(self._accounts))

    # --- the invariant the ledger can check without reading anything ----
    def total(self):
        total = self.group.identity()
        for entry in self._accounts.values():
            total = self.group.mul(total, entry.balance)
        return total

    def conserved(self) -> bool:
        """No value was created or destroyed since the accounts were opened."""
        return self.group.encode(self.total()) == self.group.encode(self._minted)

    # --- transfers ------------------------------------------------------
    def build_transfer(self, payer_balance: int, payer_blinding: int, amount: int,
                       context: bytes, tag: "BlindedTag | None" = None,
                       gamma: int = 0, amount_bounded: bool = False
                       ) -> tuple[TransferProof, TransferSecrets]:
        """Run by the payer, who is the only party that knows its own balance.

        With an asset tag the proofs are stated against H = A h^gamma instead of
        the base generator. The balance itself stays committed under the bare A,
        so the remainder proof is what ties the disguise to the real asset: no
        other tag lets the payer open balance / amount as a value in range.

        ``amount_bounded`` drops the range proof on the amount. That proof is not
        redundant in general --- without it a payer can send a negative amount,
        which drains the payee --- but it *is* redundant when the amount is tied
        to an instruction that already proved it in range, which is every
        instruction-driven settlement. Half the range proofs in a delivery
        versus payment are this one, so the caller has to say so explicitly
        rather than have it inferred.
        """
        key = self.key if tag is None else tag.key_for(self.key)
        context = _tagged_context(self.group, context, tag)
        if amount < 0:
            raise InsufficientProof("a transfer amount cannot be negative")
        if payer_balance - amount < 0:
            raise InsufficientProof(
                f"balance {payer_balance} cannot cover {amount}")
        amount_blinding = key.random_blinding()
        if amount_bounded:
            amount_commitment = key.commit(amount, amount_blinding)
            amount_range = None
        else:
            amount_commitment, amount_range, _ = prove_bounded(
                key, amount, amount_blinding, 0, self.max_balance, context + b":amt")
        remainder = payer_balance - amount
        # H^(v-q) h^t has to land on balance / amount, which costs gamma*v
        remainder_blinding = (payer_blinding - amount_blinding
                              - gamma * payer_balance) % self.group.order
        remainder_commitment, remainder_range, _ = prove_bounded(
            key, remainder, remainder_blinding, 0, self.max_balance, context + b":rem")
        proof = TransferProof(amount_commitment, amount_range,
                              remainder_commitment, remainder_range, tag)
        return proof, TransferSecrets(
            amount_blinding=amount_blinding,
            payee_delta=(gamma * amount + amount_blinding) % self.group.order,
            remainder_blinding=remainder_blinding)

    def check_transfer(self, payer: bytes, proof: TransferProof, context: bytes,
                       amount_bounded: bool = False) -> tuple[bool, str]:
        """Run by the ledger, which reads neither the balance nor the amount."""
        key = self.key if proof.tag is None else proof.tag.key_for(self.key)
        group = self.group
        context = _tagged_context(group, context, proof.tag)
        if payer not in self._accounts:
            raise KeyError("unknown payer handle")
        if amount_bounded:
            if proof.amount_range is not None:
                return False, "an externally bounded amount carries a stale range proof"
        elif proof.amount_range is None:
            return False, "the amount carries no range proof"
        elif not verify_bounded(key, proof.amount_commitment, proof.amount_range,
                                0, self.max_balance, context + b":amt"):
            return False, "amount not shown to be within the ledger range"
        if not verify_bounded(key, proof.remainder_commitment, proof.remainder_range,
                              0, self.max_balance, context + b":rem"):
            return False, "payer would be left with a negative balance"
        # the remainder must be exactly balance - amount, which the homomorphism
        # settles without anyone opening either value
        expected = group.mul(self._accounts[payer].balance,
                             group.neg(proof.amount_commitment))
        if group.encode(expected) != group.encode(proof.remainder_commitment):
            return False, "remainder does not equal balance minus amount"
        return True, "ok"

    def apply_transfer(self, payer: bytes, payee: bytes, proof: TransferProof) -> None:
        """Only called once both legs of a settlement have been checked."""
        group = self.group
        payer_entry = self._accounts[payer]
        payee_entry = self._accounts[payee]
        self._accounts[payer] = LedgerEntry(
            payer, proof.remainder_commitment, payer_entry.sequence + 1)
        self._accounts[payee] = LedgerEntry(
            payee, group.mul(payee_entry.balance, proof.amount_commitment),
            payee_entry.sequence + 1)

    def snapshot(self) -> bytes:
        """A digest of every handle and balance, for receipts and audit."""
        digest = hashlib.sha256(LEDGER_DOMAIN)
        for handle in sorted(self._accounts):
            entry = self._accounts[handle]
            digest.update(handle)
            digest.update(self.group.encode(entry.balance))
            digest.update(entry.sequence.to_bytes(8, "big"))
        return digest.digest()
