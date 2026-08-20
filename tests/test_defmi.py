"""DeFMI: settlement that cannot read what it settles.

The interesting tests are the ones where a counterparty lies. The ledger has no
plaintext to compare against, so every guarantee it offers has to come out of the
commitment arithmetic: conservation by construction, solvency by range proof,
atomicity by checking both legs before applying either.
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from defmi.ledger import ConfidentialLedger, InsufficientProof, TransferProof  # noqa: E402
from defmi.settlement import Defmi, build_package                              # noqa: E402
from zk.commit import Pedersen, prove_bounded                                  # noqa: E402
from zk.groups import make_group                                               # noqa: E402
from zk.zkpi import InstructionIssuer, SettlementVenue                         # noqa: E402

QTY, PRICE = 100, 99_990
SETTLE_CONTEXT = b"QOMM:DEFMI:DVP:v1"
SEC_BALANCE, CASH_BALANCE = 5_000, 50_000_000


@pytest.fixture(scope="module")
def group():
    return make_group("ed25519")


@pytest.fixture()
def venue(group):
    key = Pedersen(group, b"qomm:defmi:v1")
    defmi = Defmi(group, key, venue=SettlementVenue(group, key))
    issuer = InstructionIssuer(group, key)
    # blindings live with the account holders; the ledger never sees them, which
    # is why the test has to keep them itself
    state = {
        "sec": (SEC_BALANCE, key.random_blinding()),
        "cash": (CASH_BALANCE, key.random_blinding()),
        "sec:buyer": (0, key.random_blinding()),
        "cash:seller": (0, key.random_blinding()),
    }
    defmi.securities.open_account(b"sec:seller", key.commit(*state["sec"]))
    defmi.securities.open_account(b"sec:buyer", key.commit(*state["sec:buyer"]))
    defmi.cash.open_account(b"cash:buyer", key.commit(*state["cash"]))
    defmi.cash.open_account(b"cash:seller", key.commit(*state["cash:seller"]))
    return key, defmi, issuer, state


def _instruction(group, issuer, **kw):
    args = dict(asset=3, amount=QTY, price=PRICE,
                payer_handle=group.hash_to_point(b"entity-buyer"),
                payee_handle=group.hash_to_point(b"entity-seller"),
                deadline=1_500, nonce=secrets.token_bytes(32), quote_key=1_599_845,
                nodes=list(range(1, 8)), threshold=2, quorum=[1, 2, 3])
    args.update(kw)
    return issuer.issue(**args)


def _package(group, key, defmi, instruction, aux, state, quantity=QTY, price=PRICE):
    """Returns just the package; the carry matters only where we settle twice."""
    return _package_with_carry(
        group, key, defmi, instruction, aux, state, quantity, price)[0]


def _package_with_carry(group, key, defmi, instruction, aux, state,
                        quantity=QTY, price=PRICE):
    return build_package(
        group, key, instruction=instruction, securities=defmi.securities,
        cash=defmi.cash, securities_from=b"sec:seller", securities_to=b"sec:buyer",
        cash_from=b"cash:buyer", cash_to=b"cash:seller",
        quantity=quantity, price=price,
        seller_securities_balance=state["sec"][0],
        seller_securities_blinding=state["sec"][1],
        buyer_cash_balance=state["cash"][0], buyer_cash_blinding=state["cash"][1],
        instruction_amount_blinding=aux["blindings"]["amount"],
        instruction_price_blinding=aux["blindings"]["price"])


# --- the happy path -------------------------------------------------------

def test_a_valid_delivery_versus_payment_settles(group, venue):
    key, defmi, issuer, state = venue
    instruction, aux = _instruction(group, issuer)
    receipt = defmi.settle(_package(group, key, defmi, instruction, aux, state), now=1_000)
    assert receipt.status == "settled", receipt.reason
    assert defmi.verify_receipt(receipt)
    assert defmi.solvent()
    assert receipt.securities_snapshot_before != receipt.securities_snapshot_after
    assert receipt.cash_snapshot_before != receipt.cash_snapshot_after


def test_balances_carry_forward_across_settlements(group, venue):
    """A payer keeps its blindings, so it can go on proving solvency."""
    key, defmi, issuer, state = venue
    carry = None
    for _ in range(4):
        current = state if carry is None else {
            "sec": (carry.securities_balance, carry.securities_blinding),
            "cash": (carry.cash_balance, carry.cash_blinding),
        }
        instruction, aux = _instruction(group, issuer)
        package, carry = _package_with_carry(
            group, key, defmi, instruction, aux, current)
        assert defmi.settle(package, now=1_000).status == "settled"
        assert defmi.solvent()
        assert defmi.securities.conserved() and defmi.cash.conserved()
    # the seller has parted with exactly 4 lots, and can still open its balance
    assert carry.securities_balance == SEC_BALANCE - 4 * QTY
    assert group.encode(defmi.securities.balance(b"sec:seller")) == group.encode(
        key.commit(carry.securities_balance, carry.securities_blinding))


def test_a_payee_can_spend_what_it_received(group, venue):
    """Receiving is only real if the new balance is openable by its holder."""
    key, defmi, issuer, state = venue
    instruction, aux = _instruction(group, issuer)
    package, carry = _package_with_carry(group, key, defmi, instruction, aux, state)
    assert defmi.settle(package, now=1_000).status == "settled"
    # the buyer started at zero, so its blinding is the one it opened with plus
    # the amount blinding from the leg it just received
    buyer_blinding = (state["sec:buyer"][1] + carry.quantity_blinding) % group.order
    assert group.encode(defmi.securities.balance(b"sec:buyer")) == group.encode(
        key.commit(QTY, buyer_blinding))
    onward, _ = defmi.securities.build_transfer(QTY, buyer_blinding, QTY // 2, b"onward")
    ok, why = defmi.securities.check_transfer(b"sec:buyer", onward, b"onward")
    assert ok, why
    defmi.securities.apply_transfer(b"sec:buyer", b"sec:seller", onward)
    assert defmi.securities.conserved()


# --- lying counterparties -------------------------------------------------

def test_an_overdraft_cannot_be_proved(group, venue):
    key, defmi, _, state = venue
    with pytest.raises(InsufficientProof):
        defmi.securities.build_transfer(state["sec"][0], state["sec"][1],
                                        SEC_BALANCE + 1, b"ctx")


def test_a_forged_remainder_is_rejected(group, venue):
    """Skipping the payer-side check must not get past the ledger."""
    key, defmi, _, state = venue
    balance, blinding = state["sec"]
    amount = balance + 1                       # more than the account holds
    amount_blinding = key.random_blinding()
    amount_commitment, amount_range, _ = prove_bounded(
        key, amount, amount_blinding, 0, defmi.securities.max_balance, b"ctx:amt")
    # the honest remainder is negative, so the liar commits to the wrapped value
    wrapped = (balance - amount) % group.order
    remainder_blinding = (blinding - amount_blinding) % group.order
    with pytest.raises(ValueError):
        prove_bounded(key, wrapped, remainder_blinding, 0,
                      defmi.securities.max_balance, b"ctx:rem")


def test_a_cash_leg_that_is_not_quantity_times_price_is_rejected(group, venue):
    key, defmi, issuer, state = venue
    instruction, aux = _instruction(group, issuer)
    # build with a price the instruction did not commit to
    package = _package(group, key, defmi, instruction, aux, state, price=PRICE // 2)
    receipt = defmi.settle(package, now=1_000)
    assert receipt.status == "rejected"
    assert "quantity times price" in receipt.reason
    assert defmi.solvent()


def test_a_securities_leg_of_the_wrong_size_is_rejected(group, venue):
    key, defmi, issuer, state = venue
    instruction, aux = _instruction(group, issuer)
    package = _package(group, key, defmi, instruction, aux, state, quantity=QTY + 1)
    receipt = defmi.settle(package, now=1_000)
    assert receipt.status == "rejected"
    assert "instructed quantity" in receipt.reason
    assert defmi.solvent()


def test_nothing_moves_when_a_leg_fails(group, venue):
    """Atomicity: both legs are checked before either is applied."""
    key, defmi, issuer, state = venue
    before_securities = defmi.securities.snapshot()
    before_cash = defmi.cash.snapshot()
    instruction, aux = _instruction(group, issuer)
    package = _package(group, key, defmi, instruction, aux, state, price=PRICE + 7)
    receipt = defmi.settle(package, now=1_000)
    assert receipt.status == "rejected"
    assert defmi.securities.snapshot() == before_securities
    assert defmi.cash.snapshot() == before_cash


def test_an_instruction_settles_at_most_once(group, venue):
    key, defmi, issuer, state = venue
    instruction, aux = _instruction(group, issuer)
    package = _package(group, key, defmi, instruction, aux, state)
    assert defmi.settle(package, now=1_000).status == "settled"
    replay = defmi.settle(package, now=1_000)
    assert replay.status == "rejected" and "already settled" in replay.reason


def test_an_expired_instruction_does_not_settle(group, venue):
    key, defmi, issuer, state = venue
    instruction, aux = _instruction(group, issuer)
    package = _package(group, key, defmi, instruction, aux, state)
    receipt = defmi.settle(package, now=2_000)
    assert receipt.status == "rejected" and "deadline" in receipt.reason


def test_an_unknown_account_is_refused(group, venue):
    key, defmi, issuer, state = venue
    instruction, aux = _instruction(group, issuer)
    package = _package(group, key, defmi, instruction, aux, state)
    stranger = type(package)(**{**package.__dict__, "cash_to": b"cash:nobody"})
    receipt = defmi.settle(stranger, now=1_000)
    assert receipt.status == "rejected" and "not open" in receipt.reason


# --- what the ledger reveals ---------------------------------------------

def test_the_ledger_holds_commitments_not_amounts(group, venue):
    key, defmi, issuer, state = venue
    instruction, aux = _instruction(group, issuer)
    defmi.settle(_package(group, key, defmi, instruction, aux, state), now=1_000)
    encoded = b"".join(group.encode(defmi.securities.balance(h))
                       for h in defmi.securities.handles())
    for secret in (QTY, SEC_BALANCE, SEC_BALANCE - QTY):
        assert secret.to_bytes(4, "big") not in encoded


def test_receipts_are_signed_and_tamper_evident(group, venue):
    key, defmi, issuer, state = venue
    instruction, aux = _instruction(group, issuer)
    receipt = defmi.settle(_package(group, key, defmi, instruction, aux, state), now=1_000)
    assert defmi.verify_receipt(receipt)
    forged = type(receipt)(**{**receipt.__dict__, "status": "rejected"})
    assert not defmi.verify_receipt(forged)


def test_a_mismatched_commitment_key_is_refused(group):
    """Different second generators make every binding vacuous, so refuse early."""
    key = Pedersen(group, b"qomm:defmi:v1")
    with pytest.raises(ValueError, match="different commitment"):
        Defmi(group, key, venue=SettlementVenue(group, Pedersen(group, b"elsewhere")))


def test_conservation_is_checked_without_reading_balances(group):
    key = Pedersen(group, b"qomm:defmi:v1")
    ledger = ConfidentialLedger(group, key)
    ledger.open_account(b"A", key.commit(1_000, key.random_blinding()))
    ledger.open_account(b"B", key.commit(0, key.random_blinding()))
    assert ledger.conserved()
    # inventing value breaks the invariant even though nothing was opened
    ledger._accounts[b"B"] = type(ledger._accounts[b"B"])(
        b"B", key.commit(500, key.random_blinding()), 1)
    assert not ledger.conserved()


# --- asset tags: settling without knowing what is being settled -----------

@pytest.fixture()
def tagged(group):
    from defmi.assets import AssetRegistry
    key = Pedersen(group, b"qomm:defmi:v1")
    return key, AssetRegistry(group, key, 16)


def _tagged_venue(group, key, registry, asset: int):
    defmi = Defmi(group, key, venue=SettlementVenue(group, key))
    issuer = InstructionIssuer(group, key)
    asset_key = key.with_value_generator(registry.tags[asset])
    state = {"sec": (SEC_BALANCE, key.random_blinding()),
             "cash": (CASH_BALANCE, key.random_blinding())}
    defmi.securities.open_account(b"sec:seller", asset_key.commit(*state["sec"]))
    defmi.securities.open_account(b"sec:buyer",
                                  asset_key.commit(0, key.random_blinding()))
    defmi.cash.open_account(b"cash:buyer", key.commit(*state["cash"]))
    defmi.cash.open_account(b"cash:seller", key.commit(0, key.random_blinding()))
    return defmi, issuer, state


def _tagged_package(group, key, defmi, issuer, state, tag, gamma):
    instruction, aux = _instruction(group, issuer)
    package, _ = build_package(
        group, key, instruction=instruction, securities=defmi.securities,
        cash=defmi.cash, securities_from=b"sec:seller", securities_to=b"sec:buyer",
        cash_from=b"cash:buyer", cash_to=b"cash:seller", quantity=QTY, price=PRICE,
        seller_securities_balance=state["sec"][0],
        seller_securities_blinding=state["sec"][1],
        buyer_cash_balance=state["cash"][0], buyer_cash_blinding=state["cash"][1],
        instruction_amount_blinding=aux["blindings"]["amount"],
        instruction_price_blinding=aux["blindings"]["price"],
        securities_tag=tag, securities_gamma=gamma)
    return package


def test_a_tagged_settlement_goes_through(group, tagged):
    key, registry = tagged
    defmi, issuer, state = _tagged_venue(group, key, registry, asset=3)
    tag, gamma = registry.blind(3)
    receipt = defmi.settle(
        _tagged_package(group, key, defmi, issuer, state, tag, gamma), now=1_000)
    assert receipt.status == "settled", receipt.reason
    assert defmi.solvent()


def test_the_package_looks_the_same_whatever_the_asset(group, tagged):
    """Obliviousness is only worth claiming if the bytes agree.

    Compared against each other rather than against a constant: a hard-coded
    size is a number that goes stale quietly, and it would also have to agree
    with whichever sizer happened to be used.
    """
    key, registry = tagged
    seen = set()
    for asset in (0, 3, 7, 15):
        defmi, issuer, state = _tagged_venue(group, key, registry, asset)
        tag, gamma = registry.blind(asset)
        package = _tagged_package(group, key, defmi, issuer, state, tag, gamma)
        assert defmi.settle(package, now=1_000).status == "settled"
        seen.add(_wire_size(group, package))
    assert len(seen) == 1, f"asset leaks through the package size: {sorted(seen)}"


def _wire_size(group, obj) -> int:
    """Canonical size: 32 bytes for a point or a scalar, actual length for bytes."""
    import dataclasses as dc
    if dc.is_dataclass(obj):
        return sum(_wire_size(group, getattr(obj, f.name)) for f in dc.fields(obj))
    if isinstance(obj, (list, tuple)):
        return sum(_wire_size(group, item) for item in obj)
    if isinstance(obj, dict):
        return sum(_wire_size(group, k) + _wire_size(group, v)
                   for k, v in obj.items())
    if isinstance(obj, bytes):
        return len(obj)
    if isinstance(obj, bool):
        return 1
    if isinstance(obj, int):
        return 32
    if isinstance(obj, str):
        return len(obj.encode())
    return 32


def test_a_tag_for_the_wrong_asset_cannot_move_the_balance(group, tagged):
    """The remainder proof is what binds the disguise to the real asset."""
    key, registry = tagged
    defmi, issuer, state = _tagged_venue(group, key, registry, asset=3)
    wrong_tag, wrong_gamma = registry.blind(7)
    receipt = defmi.settle(
        _tagged_package(group, key, defmi, issuer, state, wrong_tag, wrong_gamma),
        now=1_000)
    assert receipt.status == "rejected"
    assert "remainder does not equal" in receipt.reason


def test_a_fabricated_tag_cannot_move_the_balance(group, tagged):
    """Nor can a point that was never on the register at all."""
    from defmi.assets import BlindedTag
    key, registry = tagged
    defmi, issuer, state = _tagged_venue(group, key, registry, asset=3)
    invented = BlindedTag(group.hash_to_point(b"not-a-listed-asset"))
    receipt = defmi.settle(
        _tagged_package(group, key, defmi, issuer, state, invented, 7), now=1_000)
    assert receipt.status == "rejected"
    assert "remainder does not equal" in receipt.reason


def test_issuance_carries_a_proof_that_the_asset_is_listed(group, tagged):
    """The one place a membership proof is actually needed."""
    key, registry = tagged
    tag, _ = registry.blind(5, prove=True)
    assert registry.verify_membership(tag)
    from defmi.assets import BlindedTag
    forged = BlindedTag(group.hash_to_point(b"invented"), tag.membership)
    assert not registry.verify_membership(forged)
    assert not registry.verify_membership(BlindedTag(tag.point))   # no proof at all


def test_an_unlisted_asset_cannot_be_blinded(group, tagged):
    _, registry = tagged
    with pytest.raises(ValueError, match="not registered"):
        registry.blind(registry.count + 1)


def test_the_register_is_padded_to_a_power_of_two(group):
    """A set that grew with each listing would leak the listing."""
    from defmi.assets import AssetRegistry
    key = Pedersen(group, b"qomm:defmi:v1")
    for count, expected in ((3, 4), (5, 8), (16, 16), (17, 32)):
        assert AssetRegistry(group, key, count).size == expected


def test_a_transfer_proof_does_not_carry_over_to_another_tag(group, tagged):
    """The tag is prover-chosen, so it belongs in the transcript."""
    from defmi.ledger import ConfidentialLedger, TransferProof
    key, registry = tagged
    ledger = ConfidentialLedger(group, key)
    tag, gamma = registry.blind(3)
    asset_key = key.with_value_generator(registry.tags[3])
    balance, blinding = SEC_BALANCE, key.random_blinding()
    ledger.open_account(b"a", asset_key.commit(balance, blinding))
    ledger.open_account(b"b", asset_key.commit(0, key.random_blinding()))
    proof, _ = ledger.build_transfer(balance, blinding, QTY, b"ctx",
                                     tag=tag, gamma=gamma)
    assert ledger.check_transfer(b"a", proof, b"ctx")[0]
    other, _ = registry.blind(9)
    swapped = TransferProof(proof.amount_commitment, proof.amount_range,
                            proof.remainder_commitment, proof.remainder_range,
                            other)
    accepted, reason = ledger.check_transfer(b"a", swapped, b"ctx")
    assert not accepted and "within the ledger range" in reason


def test_a_negative_amount_is_still_caught_without_its_own_range_proof(group, venue):
    """The settlement path drops the amount range proof; this is what replaces it.

    A payer that sends a negative amount drains the payee, so removing the
    ledger's own check is only safe because the leg is pinned to an instruction
    that proved the amount in range. If that link ever stops binding, this test
    is what notices.
    """
    key, defmi, issuer, state = venue
    instruction, aux = _instruction(group, issuer)
    stolen = (-500) % group.order
    # a leg that moves a negative amount, built by hand since build_package
    # would refuse it
    blinding = key.random_blinding()
    amount_commitment = key.commit(stolen, blinding)
    from defmi.ledger import TransferProof
    from zk.commit import prove_bounded
    remainder = state["sec"][0] - (-500)
    _, remainder_range, _ = prove_bounded(
        key, remainder, (state["sec"][1] - blinding) % group.order,
        0, defmi.securities.max_balance, SETTLE_CONTEXT + b":sec:rem")
    leg = TransferProof(amount_commitment, None,
                        key.commit(remainder, (state["sec"][1] - blinding) % group.order),
                        remainder_range, None)
    accepted, reason = defmi.securities.check_transfer(
        b"sec:seller", leg, SETTLE_CONTEXT + b":sec", amount_bounded=True)
    # the ledger alone accepts it --- that is exactly why the instruction link
    # has to be the thing that refuses
    assert accepted, reason
    package = _package(group, key, defmi, instruction, aux, state)
    tampered = type(package)(**{**package.__dict__, "securities_leg": leg})
    receipt = defmi.settle(tampered, now=1_000)
    assert receipt.status == "rejected"
    assert "instructed quantity" in receipt.reason


def test_a_stale_range_proof_on_a_bounded_amount_is_refused(group, venue):
    """Belt and braces: the mode is the ledger's call, not the submitter's."""
    key, defmi, issuer, state = venue
    leg, _ = defmi.securities.build_transfer(
        state["sec"][0], state["sec"][1], QTY, b"ctx")      # unbounded: has one
    assert leg.amount_range is not None
    accepted, reason = defmi.securities.check_transfer(
        b"sec:seller", leg, b"ctx", amount_bounded=True)
    assert not accepted and "stale range proof" in reason
