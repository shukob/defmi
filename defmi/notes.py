"""Balances that do not sit at an address.

The account ledger hides every amount and, with asset tags, every asset. What it
cannot hide is *who*: a settlement names four handles in the clear, so repeated
handles draw the trading graph even when every number in it is a commitment.

The fix is to stop having accounts. A holding is a note

    C = g^S · A_a^v · h^r

carrying a serial number S, v units of asset a, and a blinding r. Two properties
follow.

The recipient, not the sender, controls S. An address is a pair of points
(A, B) = (g^a, g^b); a sender draws an ephemeral e, publishes E = g^e, and builds
the note against g^{k}·B where k = H(A^e). That point is computable from public
data, but S = k + b is not, so the sender can address a note it cannot spend. The
recipient recovers k = H(E^a) by scanning, and every note it receives sits at a
different point --- two payments to the same address are unlinkable.

And the spender does not say which note it is spending. It publishes S, a
re-blinded value commitment C' = A_a^v h^{r'}, and a one-out-of-many proof that
some note in a ring satisfies C_i / (g^S · C') = h^{r - r'}. Only the real note
does, and the proof does not say which. Revealing S leaks nothing on its own,
because S never appeared in public before the spend and cannot be recovered from
C without the opening.

This is the Groth--Kohlweiss proof doing the job it was designed for, rather than
the asset-registry job it does in ``assets.py``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Sequence

from zk.commit import (
    OpeningProof, Pedersen, RangeProof, prove_bounded, prove_opening,
    verify_bounded, verify_opening,
)
from zk.gk_oneofmany import GkProof, GkProver, GkVerifier
from zk.groups import Group

NOTE_DOMAIN = b"qomm:defmi:note:v1"
MAX_VALUE = (1 << 40) - 1


def _scalar(group: Group, label: bytes, *parts: bytes) -> int:
    digest = hashlib.sha512(NOTE_DOMAIN + b":" + label)
    for part in parts:
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return int.from_bytes(digest.digest(), "big") % group.order


class DoubleSpend(Exception):
    """A serial number that has already been published."""


@dataclass(frozen=True)
class Address:
    """What a payee publishes. Neither half lets anyone spend."""

    view: Any
    spend: Any


class Wallet:
    """The two secrets behind an address.

    Split because they do different jobs: the view key is enough to find your
    own notes and could be handed to an auditor, while only the spend key turns
    a note into a serial number.
    """

    def __init__(self, group: Group, view: int | None = None,
                 spend: int | None = None):
        self.group = group
        self._view = view if view is not None else group.random_scalar()
        self._spend = spend if spend is not None else group.random_scalar()
        self.address = Address(group.base_pow(self._view),
                               group.base_pow(self._spend))

    def shared(self, ephemeral) -> int:
        """H(E^a), the same scalar the sender derived as H(A^e)."""
        return _scalar(self.group, b"shared",
                       self.group.encode(self.group.point_pow(ephemeral, self._view)))

    def serial(self, ephemeral) -> int:
        return (self.shared(ephemeral) + self._spend) % self.group.order


@dataclass(frozen=True)
class Note:
    """What lands on the ledger.

    The one-time point is published rather than folded into a single blob. It
    reveals nothing --- P = g^{H(A^e)}·B is unlinkable to the address without
    the view key --- and keeping it separate is what lets a settlement check
    that a note carries the value commitment its proof is about. Fold them
    together and that check has nothing to compare.
    """

    one_time: Any
    value_commitment: Any
    ephemeral: Any
    masked_value: int
    masked_blinding: int

    @property
    def commitment(self):
        raise NotImplementedError("use NoteLedger.commitment_of")


@dataclass(frozen=True)
class Opening:
    """What the owner recovers by scanning. Never published."""

    value: int
    blinding: int
    serial: int


@dataclass(frozen=True)
class SerialProof:
    """Knowledge of the discrete log of the published serial point.

    Without it the serial could be published as g^S h^u for any u the spender
    knows, which would give a fresh nullifier every time and make double
    spending free. Proving knowledge of the exponent base g rules that out,
    since an h-component would require knowing log_g h.
    """

    commitment_t: Any
    z: int


@dataclass(frozen=True)
class SpendProof:
    """One note spent into two, saying neither which one nor for how much."""

    serial_point: Any
    serial_proof: SerialProof
    pseudo_commitment: Any
    ring: GkProof
    outputs: tuple
    output_ranges: tuple
    balance: OpeningProof
    tag: Any


class NoteLedger:
    """A pool of notes, a set of spent serials, and nothing else."""

    def __init__(self, group: Group, key: Pedersen | None = None,
                 max_value: int = MAX_VALUE):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:defmi:v1")
        # the serial rides on the base point, which is independent of both the
        # asset tags and h because those come from hash-to-point
        self.max_value = max_value
        self.notes: list[Note] = []
        self.spent: set[bytes] = set()
        self._prover = GkProver(group, self.key)
        self._verifier = GkVerifier(group, self.key)

    # --- creating notes -------------------------------------------------
    def one_time_point(self, address: Address, shared: int):
        """g^k · B, which the sender can build and only the payee can open."""
        return self.group.mul(self.group.base_pow(shared), address.spend)

    def build_note(self, address: Address, value: int, asset_key: Pedersen,
                   blinding: int | None = None,
                   value_commitment=None, effective_blinding: int | None = None):
        """Run by the sender.

        ``value_commitment`` lets a spend hand in a commitment it has already
        made under a blinded tag. The note still has to be openable under the
        bare asset generator, so ``effective_blinding`` is the exponent of h in
        that form --- gamma*value larger than the one used against the tag ---
        and that is what gets masked and sent to the payee.
        """
        group = self.group
        if not 0 <= value <= self.max_value:
            raise ValueError(f"value {value} outside [0, {self.max_value}]")
        ephemeral_secret = group.random_scalar()
        ephemeral = group.base_pow(ephemeral_secret)
        shared = _scalar(group, b"shared",
                         group.encode(group.point_pow(address.view, ephemeral_secret)))
        if value_commitment is None:
            blinding = group.random_scalar() if blinding is None else blinding
            value_commitment = asset_key.commit(value, blinding)
            effective_blinding = blinding
        masks = self._masks(shared)
        note = Note(self.one_time_point(address, shared), value_commitment, ephemeral,
                    (value + masks[0]) % group.order,
                    (effective_blinding + masks[1]) % group.order)
        return note, Opening(value, effective_blinding, serial=-1), shared

    def _masks(self, shared: int) -> tuple[int, int]:
        encoded = shared.to_bytes(32, "big")
        return (_scalar(self.group, b"mask:value", encoded),
                _scalar(self.group, b"mask:blinding", encoded))

    def commitment_of(self, note: Note):
        """g^S · A^v · h^r, which is what the ring proof speaks about."""
        return self.group.mul(note.one_time, note.value_commitment)

    def add(self, note: Note) -> int:
        self.notes.append(note)
        return len(self.notes) - 1

    # --- finding your own -----------------------------------------------
    def scan(self, wallet: Wallet, asset_key: Pedersen) -> dict[int, Opening]:
        """One scalar multiplication per note; no trial decryption of amounts."""
        group = self.group
        found: dict[int, Opening] = {}
        for index, note in enumerate(self.notes):
            shared = wallet.shared(note.ephemeral)
            masks = self._masks(shared)
            value = (note.masked_value - masks[0]) % group.order
            blinding = (note.masked_blinding - masks[1]) % group.order
            if value > self.max_value:
                continue
            expected = group.mul(self.one_time_point(wallet.address, shared),
                                 asset_key.commit(value, blinding))
            if group.encode(expected) == group.encode(self.commitment_of(note)):
                found[index] = Opening(value, blinding,
                                       (shared + wallet._spend) % group.order)
        return found

    # --- spending -------------------------------------------------------
    def ring_for(self, index: int, size: int, rng) -> list[int]:
        """Decoys drawn from the pool, with the real note somewhere inside."""
        if size < 2 or size & (size - 1):
            raise ValueError("ring size must be a power of two, at least 2")
        if len(self.notes) < size:
            raise ValueError(f"pool holds {len(self.notes)} notes, ring needs {size}")
        others = [i for i in range(len(self.notes)) if i != index]
        ring = rng.sample(others, size - 1) + [index]
        rng.shuffle(ring)
        return ring

    def build_spend(self, ring: Sequence[int], index: int, opening: Opening,
                    tag, gamma: int, outputs: Sequence[tuple[Address, int]],
                    context: bytes = NOTE_DOMAIN):
        """Spend one note into several, saying neither which one nor how much.

        Everything is stated against the blinded tag H, so a verifier learns
        the shape of the transaction and nothing about the asset. The pool
        itself stays under the bare generator, which is what lets the ring
        proof bind H to the real asset: a tag for anything else leaves a
        residue no power of h can absorb.
        """
        group = self.group
        order = group.order
        tagged = tag.key_for(self.key)
        context = context + b":tag:" + group.encode(tag.point)
        position = list(ring).index(index)
        if sum(value for _, value in outputs) != opening.value:
            raise ValueError("outputs do not sum to the note being spent")

        pseudo_blinding = group.random_scalar()
        pseudo = tagged.commit(opening.value, pseudo_blinding)
        # pseudo is A^v h^(gamma*v + pseudo_blinding) in bare form
        pseudo_effective = (gamma * opening.value + pseudo_blinding) % order

        # The serial goes out as a point, never as the scalar. S = H(A^e) + b,
        # so a sender who kept the shared secret would read the payee's spend
        # key straight off a published scalar --- from the one note it addressed
        # to them. The point gives nothing away, and the sender can already
        # recognise its own note being spent whatever we publish.
        serial_point = group.base_pow(opening.serial)
        serial_proof = self._prove_serial(serial_point, opening.serial, context)

        offset = group.mul(serial_point, pseudo)
        members = [group.mul(self.commitment_of(self.notes[i]), group.neg(offset))
                   for i in ring]
        ring_proof = self._prover.prove(
            members, position, (opening.blinding - pseudo_effective) % order)

        notes, openings, ranges, commitments, tagged_blindings = [], [], [], [], 0
        for address, value in outputs:
            blinding = group.random_scalar()
            commitment = tagged.commit(value, blinding)
            note, out_opening, _ = self.build_note(
                address, value, tagged, value_commitment=commitment,
                effective_blinding=(gamma * value + blinding) % order)
            _, range_proof, _ = prove_bounded(
                tagged, value, blinding, 0, self.max_value, context + b":out")
            notes.append(note)
            openings.append(out_opening)
            ranges.append(range_proof)
            commitments.append(commitment)
            tagged_blindings = (tagged_blindings + blinding) % order

        residual = pseudo
        for commitment in commitments:
            residual = group.mul(residual, group.neg(commitment))
        balance = prove_opening(tagged, residual, 0,
                                (pseudo_blinding - tagged_blindings) % order,
                                context + b":balance")
        proof = SpendProof(serial_point, serial_proof, pseudo, ring_proof,
                           tuple(commitments), tuple(ranges), balance, tag)
        return proof, notes, openings

    def check_spend(self, ring: Sequence[int], proof: SpendProof,
                    context: bytes = NOTE_DOMAIN) -> tuple[bool, str]:
        """Run by the ledger, which learns neither the note, the amounts, nor
        the asset --- only that a spend of this shape is consistent."""
        group = self.group
        tagged = proof.tag.key_for(self.key)
        context = context + b":tag:" + group.encode(proof.tag.point)
        if group.encode(proof.serial_point) in self.spent:
            return False, "serial already spent"
        if not self._check_serial(proof.serial_point, proof.serial_proof, context):
            return False, "the serial is not a bare power of the base point"
        if any(i >= len(self.notes) for i in ring):
            return False, "ring names a note that is not in the pool"
        if len(set(ring)) != len(ring):
            return False, "ring repeats a note"

        offset = group.mul(proof.serial_point, proof.pseudo_commitment)
        members = [group.mul(self.commitment_of(self.notes[i]), group.neg(offset))
                   for i in ring]
        if not self._verifier.verify(members, proof.ring):
            return False, "no note in the ring carries this serial"

        if len(proof.outputs) != len(proof.output_ranges):
            return False, "an output is missing its range proof"
        for commitment, range_proof in zip(proof.outputs, proof.output_ranges):
            if not verify_bounded(tagged, commitment, range_proof,
                                  0, self.max_value, context + b":out"):
                return False, "an output is not shown to be in range"

        residual = proof.pseudo_commitment
        for commitment in proof.outputs:
            residual = group.mul(residual, group.neg(commitment))
        if not verify_opening(tagged, residual, proof.balance,
                              context + b":balance"):
            return False, "outputs do not add up to the note being spent"
        return True, "ok"

    def apply_spend(self, proof: SpendProof, notes: Sequence[Note]) -> list[int]:
        serial = self.group.encode(proof.serial_point)
        if serial in self.spent:
            raise DoubleSpend("serial already spent")
        self.spent.add(serial)
        return [self.add(note) for note in notes]

    def snapshot(self) -> bytes:
        """A digest of the pool and the spent set, for receipts and audit."""
        digest = hashlib.sha256(NOTE_DOMAIN)
        for note in self.notes:
            digest.update(self.group.encode(self.commitment_of(note)))
        for serial in sorted(self.spent):
            digest.update(serial)
        return digest.digest()

    # --- the serial is a point, and has to be a bare one ------------------
    def _prove_serial(self, point, serial: int, context: bytes) -> SerialProof:
        group = self.group
        witness = group.random_scalar()
        commitment_t = group.base_pow(witness)
        challenge = _scalar(group, b"serial", context,
                            group.encode(point), group.encode(commitment_t))
        return SerialProof(commitment_t,
                           (witness + challenge * serial) % group.order)

    def _check_serial(self, point, proof: SerialProof, context: bytes) -> bool:
        group = self.group
        if not (group.is_valid(point) and group.is_valid(proof.commitment_t)):
            return False
        if not 0 <= proof.z < group.order:
            return False
        challenge = _scalar(group, b"serial", context,
                            group.encode(point), group.encode(proof.commitment_t))
        left = group.base_pow(proof.z)
        right = group.mul(proof.commitment_t, group.point_pow(point, challenge))
        return group.encode(left) == group.encode(right)

    # Conservation is not a global product here, and saying so is more useful
    # than a check that always passes. Spent notes stay in the pool --- removing
    # them would say which one was spent --- so no running total can be
    # reconciled. What holds instead is per-spend: the balance proof forces the
    # outputs of every applied spend to sum to the note it consumed, and every
    # note enters the pool either at issuance or as such an output. Value is
    # conserved by induction over spends rather than by an invariant the ledger
    # can evaluate.
