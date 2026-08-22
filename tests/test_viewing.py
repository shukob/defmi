"""Handing an auditor one slice of a wallet.

`notes.py` split view from spend and said the view key "could be handed to an
auditor". It could, and that was the whole problem: one key, so handing it over
gives every instrument, every period, permanently, with no way back.

The scoping is in the address rather than in the key, so what these tests are
about is what a scope's key reaches --- and, at least as much, what it does not,
because three of the limits are permanent and a reader who assumes otherwise has
the disclosure model wrong.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from defmi.assets import AssetRegistry, asset_tag                  # noqa: E402
from defmi.notes import NoteLedger, Wallet                         # noqa: E402
from defmi.viewing import (ScopedWallet, check_grant, derive,      # noqa: E402
                           scan_scope, total_seen)
from zk.commit import Pedersen                                     # noqa: E402
from zk.groups import make_group                                   # noqa: E402

NOW = 1_780_000_000


@pytest.fixture(scope="module")
def group():
    return make_group("ed25519")


@pytest.fixture
def pool(group):
    key = Pedersen(group, b"qomm:defmi:note:v1")
    asset_key = key.with_value_generator(asset_tag(group, 3))
    ledger = NoteLedger(group, key)
    owner = ScopedWallet(group)
    return key, asset_key, ledger, owner


def fill(ledger, asset_key, owner, scopes, per_scope=5, seed=7):
    rng = random.Random(seed)
    planted = {scope: 0 for scope in scopes}
    for scope in scopes:
        for _ in range(per_scope):
            value = rng.randrange(1, 500)
            note, _, _ = ledger.build_note(owner.address(scope), value, asset_key,
                                           rng.randrange(ledger.group.order))
            ledger.add(note)
            planted[scope] += value
    return planted


# --- what a scope reaches -------------------------------------------------

def test_a_scope_sees_its_own_notes_and_no_others(group, pool):
    key, asset_key, ledger, owner = pool
    scopes = ["2026Q2:JPY", "2026Q3:JPY", "2026Q3:USD"]
    planted = fill(ledger, asset_key, owner, scopes)
    stranger = ScopedWallet(group)
    fill(ledger, asset_key, stranger, ["theirs"], per_scope=4, seed=11)

    grant = owner.grant("2026Q3:JPY", "an auditor", issued_at=NOW)
    seen = scan_scope(ledger, grant.viewer(group), asset_key)
    assert len(seen) == 5
    assert total_seen(seen) == planted["2026Q3:JPY"]


def test_a_scope_key_says_nothing_about_a_sibling_or_the_seed(group):
    """One-way derivation, which is what makes handing one out survivable."""
    owner = ScopedWallet(group, view_seed=b"a" * 32, spend_seed=b"b" * 32)
    first = derive(group, owner.view_seed, b"view", "2026Q3:JPY")
    second = derive(group, owner.view_seed, b"view", "2026Q4:JPY")
    spend = derive(group, owner.spend_seed, b"spend", "2026Q3:JPY")
    assert first != second != spend != first
    # the same scope under a different seed is a different key
    other = ScopedWallet(group, view_seed=b"c" * 32, spend_seed=b"b" * 32)
    assert derive(group, other.view_seed, b"view", "2026Q3:JPY") != first


def test_two_scopes_of_one_wallet_are_not_linkable_from_one_of_them(group, pool):
    key, asset_key, ledger, owner = pool
    fill(ledger, asset_key, owner, ["a", "b"])
    grant = owner.grant("a", "an auditor", issued_at=NOW)
    # everything the auditor holds
    held = {group.encode(grant.address.view), group.encode(grant.address.spend),
            grant.view_key}
    other = owner.address("b")
    assert group.encode(other.view) not in held
    assert group.encode(other.spend) not in held
    assert not scan_scope(ledger, grant.viewer(group), asset_key).keys() & \
        set(range(5, 10))


def test_a_view_key_cannot_spend(group, pool):
    key, asset_key, ledger, owner = pool
    fill(ledger, asset_key, owner, ["s"], per_scope=2)
    viewer = owner.grant("s", "an auditor", issued_at=NOW).viewer(group)
    with pytest.raises(PermissionError):
        viewer.serial(ledger.notes[0].ephemeral)
    with pytest.raises(PermissionError):
        viewer._spend
    # and the openings it recovers carry no serial to spend with
    for opening in scan_scope(ledger, viewer, asset_key).values():
        assert opening.serial == -1


def test_the_wallet_can_still_spend_what_it_let_an_auditor_read(group, pool):
    """A grant is a copy of a reading ability, not a transfer of anything."""
    key, asset_key, ledger, owner = pool
    registry = AssetRegistry(group, key, 16)
    fill(ledger, asset_key, owner, ["s"], per_scope=4)
    owner.grant("s", "an auditor", issued_at=NOW)

    spender = owner.wallet("s")
    found = ledger.scan(spender, asset_key)
    index, opening = next(iter(found.items()))
    assert opening.serial != -1
    tag, gamma = registry.blind(3)
    ring = ledger.ring_for(index, 2, random.Random(3))
    payee = Wallet(group)
    proof, notes, _ = ledger.build_spend(
        ring, index, opening, tag, gamma,
        [(payee.address, opening.value)])
    accepted, reason = ledger.check_spend(ring, proof)
    assert accepted, reason


# --- what it does not reach, which is the part that has to be right -------

def test_a_view_key_sees_what_arrived_and_not_what_left(group, pool):
    """Incoming only. An auditor that needs outflows needs a different disclosure."""
    key, asset_key, ledger, owner = pool
    registry = AssetRegistry(group, key, 16)
    fill(ledger, asset_key, owner, ["s"], per_scope=4)
    viewer = owner.grant("s", "an auditor", issued_at=NOW).viewer(group)
    before = total_seen(scan_scope(ledger, viewer, asset_key))

    spender = owner.wallet("s")
    index, opening = next(iter(ledger.scan(spender, asset_key).items()))
    tag, gamma = registry.blind(3)
    ring = ledger.ring_for(index, 2, random.Random(5))
    stranger = Wallet(group)
    proof, notes, _ = ledger.build_spend(ring, index, opening, tag, gamma,
                                         [(stranger.address, opening.value)])
    assert ledger.check_spend(ring, proof)[0]
    ledger.apply_spend(proof, notes)
    # the note left, and the auditor's view of the scope has not moved
    assert total_seen(scan_scope(ledger, viewer, asset_key)) == before


def test_revocation_is_the_next_scope_and_not_a_message(group, pool):
    """A granted key keeps reading that address forever, expiry or not.

    Encoded as a test because it is the limit most likely to be assumed away:
    what stops an auditor seeing next quarter is that next quarter has its own
    address, not that anything was withdrawn.
    """
    key, asset_key, ledger, owner = pool
    fill(ledger, asset_key, owner, ["s"], per_scope=2)
    grant = owner.grant("s", "an auditor", issued_at=NOW, days=1)
    viewer = grant.viewer(group)
    assert not check_grant(group, grant, owner.public_identity,
                           now=NOW + 2 * 86_400)[0]
    # a note sent to that address after the expiry is still readable
    note, _, _ = ledger.build_note(owner.address("s"), 4242, asset_key,
                                   random.Random(1).randrange(group.order))
    ledger.add(note)
    assert 4242 in [o.value for o in scan_scope(ledger, viewer, asset_key).values()]
    # nothing sent to the *next* scope is
    later, _, _ = ledger.build_note(owner.address("s+1"), 777, asset_key,
                                    random.Random(2).randrange(group.order))
    ledger.add(later)
    assert 777 not in [o.value for o in scan_scope(ledger, viewer, asset_key).values()]


# --- the grant itself -----------------------------------------------------

def test_a_grant_is_signed_current_and_about_the_address_it_names(group, pool):
    key, asset_key, ledger, owner = pool
    grant = owner.grant("s", "an auditor", issued_at=NOW, days=90)
    assert check_grant(group, grant, owner.public_identity, now=NOW + 10)[0]
    assert not check_grant(group, grant, owner.public_identity, now=NOW - 10)[0]
    ok, why = check_grant(group, grant, owner.public_identity,
                          now=NOW + 91 * 86_400)
    assert not ok and "expired" in why
    other = ScopedWallet(group)
    assert not check_grant(group, grant, other.public_identity, now=NOW + 10)[0]


def test_an_unsigned_grant_is_a_key_somebody_wrote_down(group, pool):
    key, asset_key, ledger, owner = pool
    grant = owner.grant("s", "an auditor", issued_at=NOW)
    bare = type(grant)(**{**grant.__dict__, "signature": b""})
    ok, why = check_grant(group, bare, owner.public_identity, now=NOW + 10)
    assert not ok and "wrote down" in why


def test_a_grant_whose_key_does_not_open_its_address_is_refused(group, pool):
    key, asset_key, ledger, owner = pool
    grant = owner.grant("s", "an auditor", issued_at=NOW)
    swapped = type(grant)(**{**grant.__dict__, "address": owner.address("t")})
    ok, why = check_grant(group, swapped, owner.public_identity, now=NOW + 10)
    # the signature covers the address, so this fails there first
    assert not ok and "signed" in why
    resigned = owner.identity.sign(swapped.body(group))
    swapped = type(swapped)(**{**swapped.__dict__, "signature": resigned})
    ok, why = check_grant(group, swapped, owner.public_identity, now=NOW + 10)
    assert not ok and "does not open the address" in why
