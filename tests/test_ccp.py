"""Novation as arithmetic, and what a clearing provider still has to be trusted for.

The claim this module rests on is that interposing a house between two parties
costs two multiplications and no proof, because it rewrites the obligation graph
rather than asserting anything about it. So the tests are about the rewrite
being a rewrite --- same amounts, every edge through the house, the house's book
flat --- and about the one thing it is not, which is a check on whether those
were the trades.

The last two tests are the ones that keep the claim honest. One says out loud
that the trade set is attested and not verified; the other says a position at
one provider is not netted against a position at another, because a design that
quietly did that would be inventing cross-margining.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from defmi.assets import asset_tag                                  # noqa: E402
from defmi.ccp import (Attestation, ClearingProvider,               # noqa: E402
                       ClearingRegistry, Novation, Obligation,
                       ProviderWaterfall, attestation_digest,
                       check_attestation, check_novation, for_provider,
                       net_positions)
from defmi.credit import Tranche, grant_credit                      # noqa: E402
from zk.commit import Pedersen                                      # noqa: E402
from zk.groups import make_group                                    # noqa: E402

ASSET = "an instrument"


@pytest.fixture(scope="module")
def group():
    return make_group("ed25519")


@pytest.fixture(scope="module")
def key(group):
    return Pedersen(group, b"qomm:defmi:v1").with_value_generator(asset_tag(group, 7))


@pytest.fixture
def house(group, key):
    return ClearingProvider("DeCCP-A", b"house-a", group, key)


def graph(key, n=12, participants=6, seed=3, asset=ASSET):
    rng = random.Random(seed)
    members = [f"p{i}".encode() for i in range(participants)]
    out, values = [], []
    for _ in range(n):
        payer, payee = rng.sample(members, 2)
        value = rng.randrange(1, 1000)
        values.append(value)
        out.append(Obligation(payer, payee, asset,
                              key.commit(value, key.random_blinding())))
    return out, values


def admitted_registry(group, key, house):
    margin = grant_credit(key, handle=house.handle, rail="cash", cap=5_000,
                          cap_blinding=key.random_blinding(), collateral=20_000,
                          collateral_blinding=key.random_blinding(),
                          haircut_bp=1_000, granted_at=1)
    waterfall = for_provider(
        house.name,
        defaulter_margin=key.commit(1_000, key.random_blinding()),
        defaulter_fund=key.commit(500, key.random_blinding()),
        provider_capital=key.commit(2_000, key.random_blinding()),
        mutualised=key.commit(9_000, key.random_blinding()))
    registry = ClearingRegistry(group, key)
    ok, why = registry.admit(house, margin=margin, waterfall=waterfall)
    assert ok, why
    return registry, waterfall


# --- the rewrite is a rewrite ---------------------------------------------

def test_every_edge_goes_through_the_house_and_the_book_is_flat(group, key, house):
    edges, _ = graph(key)
    novation = house.novate(edges)
    assert novation.edges == len(edges)
    assert len(novation.after) == 2 * len(edges)
    ok, why = check_novation(group, house.handle, novation)
    assert ok, why


def test_the_flat_book_needs_no_proof_at_any_size(group, key, house):
    """It is an identity. If it ever needed establishing, novation would be
    asserting something instead of rewriting the graph."""
    for n in (1, 2, 17, 64):
        novation = house.novate(graph(key, n=n, seed=n)[0])
        assert group.encode(novation.owed_to_house) == \
            group.encode(novation.owed_by_house)
        assert check_novation(group, house.handle, novation)[0]


def test_an_amount_changed_on_the_way_through_is_caught(group, key, house):
    edges, _ = graph(key)
    novation = house.novate(edges)
    after = list(novation.after)
    victim = after[4]
    after[4] = Obligation(victim.payer, victim.payee, victim.asset,
                          key.commit(1, key.random_blinding()))
    tampered = Novation(novation.house, novation.asset, novation.before,
                        tuple(after), novation.owed_to_house,
                        novation.owed_by_house)
    ok, why = check_novation(group, house.handle, tampered)
    assert not ok and "changed amount" in why


def test_an_edge_that_does_not_touch_the_house_is_caught(group, key, house):
    edges, _ = graph(key)
    novation = house.novate(edges)
    after = list(novation.after)
    after[0] = Obligation(after[0].payer, b"somebody-else", ASSET,
                          after[0].commitment)
    tampered = Novation(novation.house, novation.asset, novation.before,
                        tuple(after), novation.owed_to_house,
                        novation.owed_by_house)
    assert not check_novation(group, house.handle, tampered)[0]


def test_a_graph_that_mixes_assets_is_refused_at_the_start(group, key, house):
    """Commitments under different tags do not combine, so a mixed graph must
    fail here rather than net one instrument out as another."""
    edges, _ = graph(key)
    edges.append(Obligation(b"p0", b"p1", "a different instrument",
                            key.commit(5, key.random_blinding())))
    with pytest.raises(ValueError, match="per asset"):
        house.novate(edges)


def test_a_novation_attributed_to_another_house_is_caught(group, key, house):
    novation = house.novate(graph(key)[0])
    ok, why = check_novation(group, b"house-b", novation)
    assert not ok and "different house" in why


def test_net_positions_accumulate_without_a_proof(group, key, house):
    edges, _ = graph(key, n=20, participants=5, seed=8)
    novation = house.novate(edges)
    nets = net_positions(group, novation)
    assert set(nets) <= {f"p{i}".encode() for i in range(5)}
    # every edge appears once as an obligation and once as a claim, so the two
    # sides of the whole book are the same point
    owed = claim = group.identity()
    for obligation, entitlement in nets.values():
        owed = group.mul(owed, obligation)
        claim = group.mul(claim, entitlement)
    assert group.encode(owed) == group.encode(claim)


# --- the attestation, and what stands behind it ---------------------------

def test_an_attestation_over_a_different_trade_set_is_caught(group, key, house):
    novation = house.novate(graph(key)[0])
    other = house.novate(graph(key, seed=99)[0])
    attestation = house.attest(novation, cycle=b"cycle-1")
    ok, why = check_attestation(group, attestation, other, house.public_identity)
    assert not ok and "different trade set" in why


def test_an_attestation_signed_by_someone_else_is_caught(group, key, house):
    novation = house.novate(graph(key)[0])
    attestation = house.attest(novation, cycle=b"cycle-1")
    other = ClearingProvider("DeCCP-B", b"house-b", group, key)
    ok, why = check_attestation(group, attestation, novation,
                                other.public_identity)
    assert not ok and "not signed by" in why


def test_the_same_trades_in_a_different_cycle_do_not_share_an_attestation(group, key, house):
    novation = house.novate(graph(key)[0])
    first = house.attest(novation, cycle=b"cycle-1")
    second = house.attest(novation, cycle=b"cycle-2")
    assert first.digest != second.digest


def test_a_provider_with_no_tranche_of_its_own_is_not_admitted(group, key, house):
    margin = grant_credit(key, handle=house.handle, rail="cash", cap=5_000,
                          cap_blinding=key.random_blinding(), collateral=20_000,
                          collateral_blinding=key.random_blinding(),
                          haircut_bp=1_000, granted_at=1)
    bare = ProviderWaterfall(house.name,
                             (Tranche("mutualised pool", key.commit(1, 2)),))
    ok, why = ClearingRegistry(group, key).admit(house, margin=margin,
                                                 waterfall=bare)
    assert not ok and "costs it nothing to get wrong" in why


def test_the_providers_capital_sits_where_the_standards_put_it(key):
    waterfall = for_provider(
        "DeCCP-A", defaulter_margin=key.commit(1, 2), defaulter_fund=key.commit(3, 4),
        provider_capital=key.commit(5, 6), mutualised=key.commit(7, 8))
    names = [t.name.split(":", 1)[1] for t in waterfall.tranches]
    assert names == ["defaulter margin", "defaulter fund contribution",
                     "provider capital", "mutualised pool"]


def test_a_shortfall_draws_the_providers_capital_before_the_pool(group, key):
    """The order is the arrangement, so it is checked rather than assumed."""
    amounts = [100, 200, 400, 5_000]
    blindings = [key.random_blinding() for _ in amounts]
    waterfall = for_provider(
        "DeCCP-A", *[], **dict(zip(
            ("defaulter_margin", "defaulter_fund", "provider_capital", "mutualised"),
            [key.commit(a, b) for a, b in zip(amounts, blindings)])))
    engine = waterfall.waterfall(group, key)
    shortfall = 500                      # eats the first two, bites the third
    resolution, drawn = engine.build(
        shortfall=shortfall, shortfall_blinding=key.random_blinding(),
        balances=amounts, blindings=blindings)
    ok, why = engine.check(resolution)
    assert ok, why
    assert drawn == [100, 200, 200, 0]
    assert drawn[3] == 0, "the pool was touched before the provider's capital"


def test_an_unadmitted_provider_is_refused(group, key, house):
    registry, _ = admitted_registry(group, key, house)
    stranger = ClearingProvider("DeCCP-B", b"house-b", group, key)
    novation = stranger.novate(graph(key)[0])
    attestation = stranger.attest(novation, cycle=b"c")
    ok, why = registry.check_cycle(attestation, novation)
    assert not ok and "not an admitted provider" in why


def test_an_admitted_provider_novating_under_another_handle_is_refused(group, key, house):
    registry, _ = admitted_registry(group, key, house)
    impostor = ClearingProvider("DeCCP-A", b"house-z", group, key)
    novation = impostor.novate(graph(key)[0])
    attestation = impostor.attest(novation, cycle=b"c")
    ok, why = registry.check_cycle(attestation, novation)
    assert not ok and "handle this provider did not register" in why


def test_a_whole_cleared_cycle_checks_out(group, key, house):
    registry, _ = admitted_registry(group, key, house)
    novation = house.novate(graph(key, n=32, seed=5)[0])
    attestation = house.attest(novation, cycle=b"cycle-1")
    ok, why = registry.check_cycle(attestation, novation)
    assert ok, why


# --- what this does not establish, said out loud --------------------------

def test_the_trade_set_is_attested_and_not_verified(group, key, house):
    """A house that novates trades nobody made produces a cycle that checks out.

    Written as a test because it is the boundary of the construction. What makes
    the attestation worth relying on is the tranche the signer occupies, not the
    arithmetic --- and a reader who assumes otherwise has the trust model wrong.
    """
    registry, _ = admitted_registry(group, key, house)
    invented, _ = graph(key, n=8, seed=1234)     # nobody agreed to any of these
    novation = house.novate(invented)
    attestation = house.attest(novation, cycle=b"cycle-1")
    ok, _ = registry.check_cycle(attestation, novation)
    assert ok, "and that is the point: the arithmetic cannot tell"


def test_a_position_at_one_provider_is_not_offset_against_another(group, key):
    """Two houses, two books, and no arithmetic joining them."""
    first = ClearingProvider("DeCCP-A", b"house-a", group, key)
    second = ClearingProvider("DeCCP-B", b"house-b", group, key)
    edges, _ = graph(key, n=10, seed=11)
    a = first.novate(edges[:5])
    b = second.novate(edges[5:])
    assert check_novation(group, first.handle, a)[0]
    assert check_novation(group, second.handle, b)[0]
    # a participant present at both has two positions and no netted one
    at_a, at_b = net_positions(group, a), net_positions(group, b)
    both = set(at_a) & set(at_b)
    assert both, "the fixture should put someone at both houses"
    for handle in both:
        assert at_a[handle] != at_b[handle]
    # and nothing in the module offers to combine them
    import defmi.ccp as module
    assert not [name for name in dir(module) if "offset" in name or "cross" in name]
