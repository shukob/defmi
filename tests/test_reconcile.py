"""Agreeing with the book of record without opening anything to it.

The mechanism is `prod C_i = A_a^{sum v} h^{sum r}` and nothing else, so the
tests worth having are about what the statement does and does not say: that it
passes only for the right total, that it says nothing about where a break is,
that finding a break costs disclosure and the cost is reported, and that a
quorum can produce it without anybody holding the aggregate blinding.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from defmi.assets import asset_tag                                # noqa: E402
from defmi.reconcile import (Attestation, aggregate, check,       # noqa: E402
                             check_positions, locate_break, prove,
                             prove_by_quorum)
from zk.commit import Pedersen                                    # noqa: E402
from zk.groups import make_group                                  # noqa: E402
from zk.threshold_sigma import deal                               # noqa: E402


@pytest.fixture(scope="module")
def group():
    return make_group("ed25519")


@pytest.fixture(scope="module")
def key(group):
    """A tagged key, because a real balance carries an asset tag."""
    return Pedersen(group, b"qomm:defmi:v1").with_value_generator(asset_tag(group, 7))


def ledger(key, n=24, seed=4):
    rng = random.Random(seed)
    values = [rng.randrange(1, 10_000) for _ in range(n)]
    blindings = [key.random_blinding() for _ in range(n)]
    return values, blindings, [key.commit(v, r) for v, r in zip(values, blindings)]


def attest(total, **kw):
    base = {"register": "JASDEC", "account": "omnibus-001", "asset": "JP3633400001",
            "as_of": "2026-08-22T09:00Z"}
    base.update(kw)
    return Attestation(total=total, **base)


# --- the statement --------------------------------------------------------

def test_the_committed_balances_reconcile_without_any_of_them_opening(key):
    values, blindings, commitments = ledger(key)
    rec = prove(key, commitments, blindings, attest(sum(values)))
    ok, why = check(key, commitments, rec)
    assert ok and why == ""


def test_only_the_right_total_verifies(key):
    values, blindings, commitments = ledger(key)
    for wrong in (sum(values) + 1, sum(values) - 1, 0):
        rec = prove(key, commitments, blindings, attest(wrong))
        ok, why = check(key, commitments, rec)
        assert not ok and "do not sum to" in why


def test_the_proof_is_about_this_account_at_this_moment(key):
    """The attestation is bound in, so a proof cannot be moved to another one."""
    values, blindings, commitments = ledger(key)
    rec = prove(key, commitments, blindings, attest(sum(values)))
    moved = type(rec)(attestation=attest(sum(values), account="omnibus-002"),
                      positions=rec.positions, proof=rec.proof)
    assert not check(key, commitments, moved)[0]
    later = type(rec)(attestation=attest(sum(values), as_of="2026-08-23T09:00Z"),
                      positions=rec.positions, proof=rec.proof)
    assert not check(key, commitments, later)[0]


def test_a_different_set_of_positions_is_refused_rather_than_reinterpreted(key):
    values, blindings, commitments = ledger(key)
    rec = prove(key, commitments, blindings, attest(sum(values)))
    ok, why = check(key, commitments[:-1], rec)
    assert not ok and "positions" in why


def test_the_wrong_asset_generator_does_not_verify(key, group):
    """A tagged balance reconciled under the base generator, which used to pass.

    `prove_linear` divided the total out with `group.base_pow`, which is the
    same point as the key's generator only when the key has no tag. On a tagged
    ledger it was the wrong generator and the answer would have been wrong
    rather than an error.
    """
    values, blindings, commitments = ledger(key)
    rec = prove(key, commitments, blindings, attest(sum(values)))
    untagged = Pedersen(group, b"qomm:defmi:v1")
    assert not check(untagged, commitments, rec)[0]


def test_an_unsigned_attestation_is_only_as_good_as_the_number_it_carries(key):
    """Reconciling against a figure somebody typed is not reconciling."""
    values, blindings, commitments = ledger(key)
    registrar = Ed25519PrivateKey.generate()
    signed = attest(sum(values))
    signed = type(signed)(**{**signed.__dict__,
                             "signature": registrar.sign(signed.body())})
    rec = prove(key, commitments, blindings, signed)
    assert check(key, commitments, rec, registrar=registrar.public_key())[0]
    # the same proof with a signature nobody checked
    assert not check(key, commitments, rec)[0]
    # and a signature from the wrong registrar
    other = Ed25519PrivateKey.generate()
    assert not check(key, commitments, rec, registrar=other.public_key())[0]


# --- a break --------------------------------------------------------------

def test_a_break_is_pass_or_fail_and_says_nothing_about_where(key):
    values, blindings, commitments = ledger(key)
    register = list(values)
    register[9] += 5
    rec = prove(key, commitments, blindings, attest(sum(register)))
    ok, why = check(key, commitments, rec)
    assert not ok
    assert "says nothing about where" in why
    assert "9" not in why.replace(str(sum(register)), "")


@pytest.mark.parametrize("n", [16, 64, 256])
def test_finding_a_break_costs_about_two_log_n_and_reports_it(key, n):
    values, blindings, commitments = ledger(key, n=n, seed=n)
    register = list(values)
    register[n // 3] += 5
    search = locate_break(key, commitments, blindings,
                          claimed=lambda a, b: sum(register[a:b]),
                          expected=sum(register))
    assert search.found == [n // 3]
    assert search.proofs == 2 * (n.bit_length() - 1) + 1
    # the narrowest range made public covers one position, which is a balance
    assert min(high - low for low, high, _ in search.ranges_made_public) == 1
    assert "sub-totals now public" in search.cost


def test_a_register_that_holds_only_a_total_cannot_localise(key):
    """There is nothing here that finds a break without somebody claiming subtotals."""
    values, blindings, commitments = ledger(key, n=8)
    register_total = sum(values) + 1

    def only_the_total(low, high):
        if (low, high) != (0, len(values)):
            raise LookupError("this register holds one figure for the account")
        return register_total

    with pytest.raises(LookupError):
        locate_break(key, commitments, blindings, claimed=only_the_total,
                     expected=register_total)


def test_a_register_with_a_figure_per_position_localises_and_discloses_nothing(key):
    values, blindings, commitments = ledger(key, n=32)
    register = list(values)
    register[7] += 1
    register[20] -= 3
    assert check_positions(key, commitments, blindings, register) == [7, 20]
    assert check_positions(key, commitments, blindings, values) == []


# --- when nobody holds the aggregate blinding ------------------------------

def test_a_quorum_assembles_it_without_anyone_holding_the_sum(key, group):
    values, blindings, commitments = ledger(key)
    shares = deal(key, 0, sum(blindings) % group.order,
                  parties=list(range(1, 8)), threshold=2)
    rec = prove_by_quorum(key, commitments, shares, quorum=[1, 3, 5],
                          attestation=attest(sum(values)))
    assert check(key, commitments, rec)[0]
    assert rec.quorum == (1, 3, 5)
    assert rec.transcript["bad_partials"] == []


def test_shares_of_the_wrong_blinding_are_refused_before_a_proof_is_made(key, group):
    values, blindings, commitments = ledger(key)
    shares = deal(key, 0, (sum(blindings) + 1) % group.order,
                  parties=list(range(1, 8)), threshold=2)
    with pytest.raises(ValueError, match="not the one these commitments"):
        prove_by_quorum(key, commitments, shares, quorum=[1, 3, 5],
                        attestation=attest(sum(values)))


def test_the_note_rail_needs_no_special_case(group):
    """A note publishes its value commitment, so the product has the same shape."""
    from defmi.notes import NoteLedger, Wallet

    key = Pedersen(group, b"qomm:defmi:note:v1")
    tag = asset_tag(group, 3)
    asset_key = key.with_value_generator(tag)
    book = NoteLedger(group, key)
    wallet = Wallet(group)
    rng = random.Random(2)
    notes, blindings, values = [], [], []
    for _ in range(6):
        value = rng.randrange(1, 500)
        note, opening, _ = book.build_note(wallet.address, value, asset_key,
                                           rng.randrange(group.order))
        notes.append(note)
        values.append(value)
        blindings.append(opening.blinding)
    commitments = [note.value_commitment for note in notes]
    rec = prove(asset_key, commitments, blindings, attest(sum(values)))
    assert check(asset_key, commitments, rec)[0]
    assert aggregate(group, commitments) is not None
