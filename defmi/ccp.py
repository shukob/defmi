"""DeCCP: the clearing house as a slot, and novation as arithmetic.

**This is the reference prototype. `rust/qomm-defmi/src/ccp.rs` is the one to
read.** The port closes the two holes this file states and leaves open: there,
both parties sign their own obligation so a house cannot novate a trade nobody
agreed to, and a member cleared at two houses gets two resolutions with the
refusal to offset written into the type. What is kept here is the measurement
the first table was taken against, and the shape of the argument.

`netting.py` measured the thing this module exists for. Netting the rails saved
only 1.73x, because 26.5 ms of every order is the payment instruction and an
instruction does not net. Signing the whole cycle instead removed it --- 17.95x
--- and the note beside that number said what it cost: the layer stops checking
individual trades, so the split between participants is attested rather than
verified, "the same bargain a central counterparty represents, made explicit."

**That note was one step short.** Under novation there is no split left to
verify, because there are no bilateral claims left to split. A trade between A
and B becomes A against the clearing house and the clearing house against B, and
after that the original obligation does not exist --- which is not a bookkeeping
convenience, it is the legal effect the institution is for. Verifying an
allocation that has been extinguished is not a check anybody was owed.

**And novation is free here.** An obligation is a commitment `A_a^v h^r`, and
replacing one edge with two is

    owed_to[house] *= C        owed_by[house] *= C

--- two multiplications, no proof, because nothing is being asserted. The
product over the graph is unchanged by construction, and the house's book is
flat by the same construction: it owes exactly what it is owed, per asset, so
`prod(owed to) == prod(owed by)` is one comparison rather than a statement
somebody has to establish. Conservation was already free in this design; this is
the same homomorphism doing the same work one level up.

**So the trust does not vanish. It moves.** What used to be a per-trade proof
becomes a named party's attestation, and what makes the attestation worth
anything is not that it is signed --- it is that the signer's own capital sits
in the default waterfall, at the tranche between the defaulting member's fund
contribution and the mutualised pool, where CPMI-IOSCO and EMIR put it.
`credit.py` already enforces tranche order over commitments, so the provider
plugs into a waterfall rather than needing a new one.

**A slot rather than a dependency.** A deployment names its clearing providers;
several may coexist and a participant's trades are novated by the one it cleared
through. Nothing in `netting.py` or `settlement.py` knows which. That is the
shape of a credit-oracle plugin, and the reason to take it here is the same:
whose balance sheet stands behind a market is a question about that market, not
about the protocol.

**Four limits, since this is the part where a design starts sounding like an
institution.**

*Per asset, not across.* Commitments under different asset tags do not combine,
so an obligation graph is per asset and the flat-book check is per asset. A
novation that mixed instruments fails the check rather than netting across them.

*Several providers make the waterfall a forest.* Only the provider that novated
the defaulting trades should be drawn before the mutualised pool. That is
structure, not a parameter, and `ProviderWaterfall` is the shape of it ---
cross-provider margin offsetting is a different problem and is not solved here.

*Free arithmetically is not valid legally.* Under a book-entry regime the
obligations here are a mirror of a register, and whether novation on the mirror
has effect is a question for that register's rulebook. `COMPLIANCE_JA.md`
section 3.2 is the position; nothing in this file changes it.

*And the house is not audited by this.* What anyone can check is that its book
is flat, that its margin is posted and that the waterfall drew in order. That
the trade set it novated is the trade set that happened is its attestation, and
no arrangement of commitments makes that checkable from outside.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from zk.commit import Pedersen
from zk.groups import Group

from .credit import CreditLine, DefaultWaterfall, Tranche, check_credit

CCP_DOMAIN = b"QOMM:DEFMI:CCP:v1"


@dataclass(frozen=True)
class Obligation:
    """One side owing another, with the amount committed and nothing else."""

    payer: bytes
    payee: bytes
    asset: str
    commitment: Any

    def body(self, group: Group) -> bytes:
        return (len(self.payer).to_bytes(4, "big") + self.payer
                + len(self.payee).to_bytes(4, "big") + self.payee
                + self.asset.encode() + b":" + group.encode(self.commitment))


@dataclass(frozen=True)
class Novation:
    """A graph of obligations rewritten so every edge touches the house.

    `before` and `after` are kept because the whole claim is that the second is
    the first with one party interposed, and a reader who cannot see both has to
    take that on trust.
    """

    house: bytes
    asset: str
    before: tuple
    after: tuple
    owed_to_house: Any
    owed_by_house: Any

    @property
    def edges(self) -> int:
        return len(self.before)


class ClearingProvider:
    """One clearing house: it novates, it attests, and it is in the waterfall.

    Deliberately small. Everything a provider does that anybody else has to
    check is arithmetic on commitments; the one thing that is not --- that these
    were the trades --- is a signature, and the reason to believe a signature is
    the capital behind it rather than the key that made it.
    """

    def __init__(self, name: str, handle: bytes, group: Group, key: Pedersen,
                 identity: Ed25519PrivateKey | None = None):
        self.name = name
        self.handle = handle
        self.group = group
        self.key = key
        self.identity = identity or Ed25519PrivateKey.generate()

    @property
    def public_identity(self) -> Ed25519PublicKey:
        return self.identity.public_key()

    # --- novation ---------------------------------------------------------

    def novate(self, obligations: Sequence[Obligation]) -> Novation:
        """Interpose this house between every pair. Two multiplications an edge.

        No proof is produced because none is needed: the operation rewrites the
        graph and leaves the product over it where it was. What a verifier does
        afterwards is `check_novation`, which re-does the same arithmetic.
        """
        if not obligations:
            raise ValueError("nothing to novate")
        assets = {o.asset for o in obligations}
        if len(assets) != 1:
            raise ValueError(f"an obligation graph is per asset; got {sorted(assets)}")
        group = self.group
        asset = assets.pop()
        after, to_house, by_house = [], group.identity(), group.identity()
        for edge in obligations:
            after.append(Obligation(edge.payer, self.handle, asset, edge.commitment))
            after.append(Obligation(self.handle, edge.payee, asset, edge.commitment))
            to_house = group.mul(to_house, edge.commitment)
            by_house = group.mul(by_house, edge.commitment)
        return Novation(house=self.handle, asset=asset,
                        before=tuple(obligations), after=tuple(after),
                        owed_to_house=to_house, owed_by_house=by_house)

    # --- the attestation, which is the only thing that is not arithmetic ---

    def attest(self, novation: Novation, *, cycle: bytes) -> "Attestation":
        digest = attestation_digest(self.group, novation, cycle)
        return Attestation(provider=self.name, handle=self.handle, cycle=cycle,
                           digest=digest, signature=self.identity.sign(digest),
                           edges=novation.edges, asset=novation.asset)


@dataclass(frozen=True)
class Attestation:
    """That these were the trades. The one claim nobody else can check."""

    provider: str
    handle: bytes
    cycle: bytes
    digest: bytes
    signature: bytes
    edges: int
    asset: str


def attestation_digest(group: Group, novation: Novation, cycle: bytes) -> bytes:
    running = hashlib.sha256(CCP_DOMAIN + b":novation:" + cycle
                             + novation.house + novation.asset.encode())
    for edge in novation.before:
        running.update(edge.body(group))
    return running.digest()


# --- what anyone can check ------------------------------------------------

def check_novation(group: Group, house: bytes,
                   novation: Novation) -> tuple[bool, str]:
    """That the second graph is the first with one party interposed.

    Every edge is replaced by exactly two, both carrying the same commitment,
    and the house's book is flat. None of it needs a proof --- it is the same
    arithmetic done again by somebody with no secrets.
    """
    if novation.house != house:
        return False, "novated by a different house than the one being checked"
    if len(novation.after) != 2 * len(novation.before):
        return False, (f"{len(novation.before)} edges became "
                       f"{len(novation.after)}, not {2 * len(novation.before)}")
    to_house = by_house = group.identity()
    for index, edge in enumerate(novation.before):
        first, second = novation.after[2 * index], novation.after[2 * index + 1]
        if first.payer != edge.payer or first.payee != house:
            return False, f"edge {index} does not run from its payer to the house"
        if second.payer != house or second.payee != edge.payee:
            return False, f"edge {index} does not run from the house to its payee"
        if group.encode(first.commitment) != group.encode(edge.commitment) or \
                group.encode(second.commitment) != group.encode(edge.commitment):
            return False, f"edge {index} changed amount on the way through"
        if edge.asset != novation.asset or first.asset != novation.asset \
                or second.asset != novation.asset:
            return False, f"edge {index} is in another asset"
        to_house = group.mul(to_house, first.commitment)
        by_house = group.mul(by_house, second.commitment)
    if group.encode(to_house) != group.encode(novation.owed_to_house) or \
            group.encode(by_house) != group.encode(novation.owed_by_house):
        return False, "the published totals are not the totals of the edges"
    if group.encode(to_house) != group.encode(by_house):
        return False, ("the house's book is not flat: it owes something other "
                       "than what it is owed")
    return True, ""


def check_attestation(group: Group, attestation: Attestation, novation: Novation,
                      provider: Ed25519PublicKey) -> tuple[bool, str]:
    """That a named provider stood behind this trade set.

    Checking a signature is not checking the trades. What makes the signature
    worth relying on is the tranche the signer occupies, and that is the next
    function down.
    """
    expected = attestation_digest(group, novation, attestation.cycle)
    if attestation.digest != expected:
        return False, "the attestation is over a different trade set"
    try:
        provider.verify(attestation.signature, attestation.digest)
    except (InvalidSignature, ValueError):
        return False, f"not signed by {attestation.provider}"
    return True, ""


def net_positions(group: Group, novation: Novation) -> dict[bytes, tuple]:
    """Each participant's obligation to the house and claim on it.

    Two products a participant, and no proof anywhere --- which is the point:
    a net position under novation is not derived, it is accumulated.
    """
    out: dict[bytes, list] = {}
    for edge in novation.after:
        if edge.payer == novation.house:
            slot = out.setdefault(edge.payee, [group.identity(), group.identity()])
            slot[1] = group.mul(slot[1], edge.commitment)
        else:
            slot = out.setdefault(edge.payer, [group.identity(), group.identity()])
            slot[0] = group.mul(slot[0], edge.commitment)
    return {handle: tuple(pair) for handle, pair in out.items()}


# --- the waterfall the provider is in -------------------------------------

@dataclass(frozen=True)
class ProviderWaterfall:
    """The default order, with one provider's own capital inside it.

    Four layers is the standard arrangement and the order is the arrangement:
    the defaulter's margin, the defaulter's contribution to the fund, **the
    clearing provider's own capital**, then everybody else's contributions.
    The third layer is why a provider's attestation is worth relying on --- it
    is the layer that makes attesting expensive to get wrong.

    With more than one provider this is a forest and not a list: only the
    provider that novated the defaulting trades stands before the pool. That is
    what `for_provider` builds, and what it deliberately does not do is offset a
    position at one provider against a position at another.
    """

    provider: str
    tranches: tuple

    def waterfall(self, group: Group, key: Pedersen,
                  max_value: int | None = None) -> DefaultWaterfall:
        kwargs = {} if max_value is None else {"max_value": max_value}
        return DefaultWaterfall(group, key, list(self.tranches), **kwargs)


def for_provider(provider: str, *, defaulter_margin, defaulter_fund,
                 provider_capital, mutualised) -> ProviderWaterfall:
    """The four layers in the order CPMI-IOSCO puts them."""
    return ProviderWaterfall(provider=provider, tranches=(
        Tranche(f"{provider}:defaulter margin", defaulter_margin),
        Tranche(f"{provider}:defaulter fund contribution", defaulter_fund),
        Tranche(f"{provider}:provider capital", provider_capital),
        Tranche(f"{provider}:mutualised pool", mutualised)))


@dataclass
class ClearingRegistry:
    """Which providers a deployment accepts, and on what terms.

    A slot rather than a dependency: nothing in `netting.py` or `settlement.py`
    knows which house cleared a trade, and a deployment with no provider at all
    is the bilateral case, which still works and pays per-trade proofs for it.
    """

    group: Group
    key: Pedersen
    providers: dict = field(default_factory=dict)

    def admit(self, provider: ClearingProvider, *, margin: CreditLine,
              waterfall: ProviderWaterfall,
              max_credit: int | None = None) -> tuple[bool, str]:
        """A provider is admitted only with margin posted and a tranche of its own."""
        kwargs = {} if max_credit is None else {"max_credit": max_credit}
        ok, reason = check_credit(self.key, margin, **kwargs)
        if not ok:
            return False, f"{provider.name}: margin does not check out --- {reason}"
        names = [t.name for t in waterfall.tranches]
        if not any("provider capital" in name for name in names):
            return False, (f"{provider.name}: no tranche of its own, so its "
                           f"attestation costs it nothing to get wrong")
        self.providers[provider.name] = {
            "handle": provider.handle, "identity": provider.public_identity,
            "margin": margin, "waterfall": waterfall}
        return True, ""

    def check_cycle(self, attestation: Attestation,
                    novation: Novation) -> tuple[bool, str]:
        """Everything a third party can establish about one cleared cycle."""
        entry = self.providers.get(attestation.provider)
        if entry is None:
            return False, f"{attestation.provider} is not an admitted provider"
        if entry["handle"] != novation.house:
            return False, "novated under a handle this provider did not register"
        ok, reason = check_novation(self.group, entry["handle"], novation)
        if not ok:
            return False, reason
        return check_attestation(self.group, attestation, novation,
                                 entry["identity"])
