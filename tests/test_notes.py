"""Notes: holdings that do not sit at an address.

Asset tags stopped the ledger learning *what* settles. These tests are about
*who*. The properties worth checking are the ones a fixed-handle ledger cannot
have: that a payee's notes are unlinkable to each other, that a spend does not
say which note it spent, and that the party who addressed a note cannot spend it.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from defmi.assets import AssetRegistry, BlindedTag          # noqa: E402
from defmi.notes import DoubleSpend, NoteLedger, Wallet     # noqa: E402
from zk.commit import Pedersen                              # noqa: E402
from zk.groups import make_group                            # noqa: E402

ASSET, RING = 3, 8


@pytest.fixture(scope="module")
def group():
    return make_group("ed25519")


@pytest.fixture()
def pool(group):
    key = Pedersen(group, b"qomm:defmi:v1")
    registry = AssetRegistry(group, key, 16)
    ledger = NoteLedger(group, key)
    asset_key = key.with_value_generator(registry.tags[ASSET])
    alice, bob = Wallet(group), Wallet(group)
    for i in range(RING):
        owner = alice.address if i == 0 else Wallet(group).address
        note, _, _ = ledger.build_note(owner, 1_000 + i, asset_key)
        ledger.add(note)
    return key, registry, ledger, asset_key, alice, bob


def _spend(group, pool, *, outputs=None, tag_asset=ASSET, seed=7):
    key, registry, ledger, asset_key, alice, bob = pool
    found = ledger.scan(alice, asset_key)
    index = next(iter(found))
    opening = found[index]
    tag, gamma = registry.blind(tag_asset)
    ring = ledger.ring_for(index, RING, random.Random(seed))
    if outputs is None:
        outputs = [(bob.address, 400), (alice.address, opening.value - 400)]
    return ring, ledger.build_spend(ring, index, opening, tag, gamma, outputs)


# --- the happy path -------------------------------------------------------

def test_a_spend_verifies_and_the_payee_can_find_its_note(group, pool):
    key, registry, ledger, asset_key, alice, bob = pool
    ring, (proof, notes, _) = _spend(group, pool)
    accepted, reason = ledger.check_spend(ring, proof)
    assert accepted, reason
    ledger.apply_spend(proof, notes)
    received = ledger.scan(bob, asset_key)
    assert [o.value for o in received.values()] == [400]


def test_two_payments_to_one_address_are_unlinkable(group, pool):
    """Same payee, different points: the ledger sees no repeat."""
    key, registry, ledger, asset_key, alice, bob = pool
    first, _, _ = ledger.build_note(bob.address, 100, asset_key)
    second, _, _ = ledger.build_note(bob.address, 100, asset_key)
    assert group.encode(ledger.commitment_of(first)) != group.encode(ledger.commitment_of(second))
    assert group.encode(first.ephemeral) != group.encode(second.ephemeral)
    ledger.add(first)
    ledger.add(second)
    assert len(ledger.scan(bob, asset_key)) == 2       # but bob finds both


def test_scanning_finds_only_your_own(group, pool):
    key, registry, ledger, asset_key, alice, bob = pool
    assert len(ledger.scan(alice, asset_key)) == 1
    assert ledger.scan(bob, asset_key) == {}
    assert ledger.scan(Wallet(group), asset_key) == {}


# --- who can spend --------------------------------------------------------

def test_the_sender_cannot_spend_the_note_it_addressed(group, pool):
    """The sender builds g^S but never learns S, which needs the spend key."""
    key, registry, ledger, asset_key, alice, bob = pool
    note, opening, shared = ledger.build_note(bob.address, 500, asset_key)
    index = ledger.add(note)
    # the sender knows the value, the blinding and the shared secret --- all of
    # it except the one scalar that turns the note into a serial number
    assert ledger.scan(bob, asset_key)[index].serial != shared
    forged = type(opening)(opening.value, opening.blinding, serial=shared)
    tag, gamma = registry.blind(ASSET)
    ring = ledger.ring_for(index, RING, random.Random(3))
    proof, _, _ = ledger.build_spend(ring, index, forged, tag, gamma,
                                     [(alice.address, 500)])
    accepted, reason = ledger.check_spend(ring, proof)
    assert not accepted and "carries this serial" in reason


def test_a_stranger_cannot_spend_your_note(group, pool):
    key, registry, ledger, asset_key, alice, bob = pool
    stranger = Wallet(group)
    found = ledger.scan(alice, asset_key)
    index = next(iter(found))
    theirs = found[index]
    # the stranger guesses everything but the serial
    guess = type(theirs)(theirs.value, theirs.blinding,
                         serial=stranger._spend)
    tag, gamma = registry.blind(ASSET)
    ring = ledger.ring_for(index, RING, random.Random(5))
    proof, _, _ = ledger.build_spend(ring, index, guess, tag, gamma,
                                     [(stranger.address, theirs.value)])
    accepted, _ = ledger.check_spend(ring, proof)
    assert not accepted


def test_a_note_spends_once(group, pool):
    key, registry, ledger, asset_key, alice, bob = pool
    ring, (proof, notes, _) = _spend(group, pool)
    assert ledger.check_spend(ring, proof)[0]
    ledger.apply_spend(proof, notes)
    accepted, reason = ledger.check_spend(ring, proof)
    assert not accepted and "already spent" in reason
    with pytest.raises(DoubleSpend):
        ledger.apply_spend(proof, notes)


# --- what a spend cannot do ----------------------------------------------

def test_outputs_must_sum_to_the_note(group, pool):
    key, registry, ledger, asset_key, alice, bob = pool
    with pytest.raises(ValueError, match="do not sum"):
        _spend(group, pool, outputs=[(bob.address, 400), (alice.address, 9_999)])


def test_a_forged_balance_is_caught(group, pool):
    """Skipping the payer-side check must not get value past the ledger."""
    key, registry, ledger, asset_key, alice, bob = pool
    ring, (proof, notes, _) = _spend(group, pool)
    inflated = type(proof)(proof.serial_point, proof.serial_proof,
                           proof.pseudo_commitment, proof.ring,
                           proof.outputs[:1], proof.output_ranges[:1],
                           proof.balance, proof.tag)
    accepted, reason = ledger.check_spend(ring, inflated)
    assert not accepted and "add up" in reason


def test_a_tag_for_the_wrong_asset_cannot_spend(group, pool):
    key, registry, ledger, asset_key, alice, bob = pool
    ring, (proof, _, _) = _spend(group, pool, tag_asset=ASSET + 4)
    accepted, reason = ledger.check_spend(ring, proof)
    assert not accepted and "carries this serial" in reason


def test_a_fabricated_tag_cannot_spend(group, pool):
    key, registry, ledger, asset_key, alice, bob = pool
    found = ledger.scan(alice, asset_key)
    index = next(iter(found))
    invented = BlindedTag(group.hash_to_point(b"not-a-listed-asset"))
    ring = ledger.ring_for(index, RING, random.Random(11))
    proof, _, _ = ledger.build_spend(ring, index, found[index], invented, 9,
                                     [(bob.address, found[index].value)])
    assert not ledger.check_spend(ring, proof)[0]


def test_a_ring_that_repeats_a_note_is_refused(group, pool):
    key, registry, ledger, asset_key, alice, bob = pool
    ring, (proof, _, _) = _spend(group, pool)
    doubled = list(ring)
    doubled[1] = doubled[0]
    accepted, reason = ledger.check_spend(doubled, proof)
    assert not accepted and "repeats" in reason


def test_the_ring_has_to_be_a_power_of_two(group, pool):
    key, registry, ledger, asset_key, alice, bob = pool
    with pytest.raises(ValueError, match="power of two"):
        ledger.ring_for(0, 6, random.Random(1))
    with pytest.raises(ValueError, match="pool holds"):
        ledger.ring_for(0, 64, random.Random(1))


# --- what a spend reveals -------------------------------------------------

def test_the_spend_looks_the_same_wherever_the_real_note_sits(group, pool):
    """The whole point: the proof must not vary with the hidden index."""
    key, registry, ledger, asset_key, alice, bob = pool
    sizes = set()
    for seed in range(6):
        ring, (proof, _, _) = _spend(group, pool, seed=seed)
        assert ledger.check_spend(ring, proof)[0]
        sizes.add(_wire_size(group, proof))
    assert len(sizes) == 1, f"the hidden position leaks: {sorted(sizes)}"


def test_the_pool_keeps_spent_notes(group, pool):
    """Removing them would say which one went."""
    key, registry, ledger, asset_key, alice, bob = pool
    before = [group.encode(ledger.commitment_of(n)) for n in ledger.notes]
    ring, (proof, notes, _) = _spend(group, pool)
    ledger.apply_spend(proof, notes)
    after = [group.encode(ledger.commitment_of(n)) for n in ledger.notes]
    assert after[:len(before)] == before


def _wire_size(group, obj) -> int:
    import dataclasses as dc
    if dc.is_dataclass(obj):
        return sum(_wire_size(group, getattr(obj, f.name)) for f in dc.fields(obj))
    if isinstance(obj, (list, tuple)):
        return sum(_wire_size(group, item) for item in obj)
    if isinstance(obj, dict):
        return sum(_wire_size(group, k) + _wire_size(group, v) for k, v in obj.items())
    if isinstance(obj, bytes):
        return len(obj)
    if isinstance(obj, bool):
        return 1
    if isinstance(obj, int):
        return 32
    if isinstance(obj, str):
        return len(obj.encode())
    return 32


# --- the serial must not give the spend key away --------------------------

def test_a_spend_never_publishes_the_serial_scalar(group, pool):
    """S = H(A^e) + b, so a published scalar hands the sender the spend key."""
    key, registry, ledger, asset_key, alice, bob = pool
    found = ledger.scan(alice, asset_key)
    index = next(iter(found))
    serial = found[index].serial
    ring, (proof, _, _) = _spend(group, pool)
    published = _scalars_in(proof)
    assert serial not in published
    # and the point that is published does not yield it either
    assert group.encode(proof.serial_point) == group.encode(group.base_pow(serial))


def _scalars_in(obj) -> set:
    import dataclasses as dc
    if dc.is_dataclass(obj):
        out = set()
        for f in dc.fields(obj):
            out |= _scalars_in(getattr(obj, f.name))
        return out
    if isinstance(obj, (list, tuple)):
        out = set()
        for item in obj:
            out |= _scalars_in(item)
        return out
    if isinstance(obj, int) and not isinstance(obj, bool):
        return {obj}
    return set()


def test_a_reblinded_serial_cannot_stand_in_for_a_fresh_one(group, pool):
    """Otherwise every spend could mint itself a new nullifier."""
    key, registry, ledger, asset_key, alice, bob = pool
    ring, (proof, notes, _) = _spend(group, pool)
    ledger.apply_spend(proof, notes)
    # shift the serial by a known power of h and try again
    shifted = group.mul(proof.serial_point, group.point_pow(key.h, 12345))
    replay = type(proof)(shifted, proof.serial_proof, proof.pseudo_commitment,
                         proof.ring, proof.outputs, proof.output_ranges,
                         proof.balance, proof.tag)
    accepted, reason = ledger.check_spend(ring, replay)
    assert not accepted and "bare power" in reason


def test_a_wrapped_negative_output_is_caught(group, pool):
    """Balancing modulo the group order must not buy anything."""
    key, registry, ledger, asset_key, alice, bob = pool
    found = ledger.scan(alice, asset_key)
    index = next(iter(found))
    opening = found[index]
    tag, gamma = registry.blind(ASSET)
    ring = ledger.ring_for(index, RING, random.Random(2))
    stolen = 10_000
    outputs = [(bob.address, opening.value + stolen),
               (alice.address, (-stolen) % group.order)]
    with pytest.raises(ValueError):
        # either the sum check or the range bound refuses it; both are the point
        ledger.build_spend(ring, index, opening, tag, gamma, outputs)
