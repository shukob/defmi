"""Asset tags that the settlement layer can carry but cannot read.

A balance of q units of asset a is committed as A_a^q h^r, where A_a is a
generator derived from the asset identifier. Two consequences follow from
nothing more than the independence of the generators.

Conservation holds *per asset* even though the ledger only ever checks one
aggregate product. Commitments under different tags do not combine into a valid
commitment under either, so there is no way to walk units of one asset out as
units of another --- not because the ledger checks for it, but because the
prover would need a discrete log between two independent generators to make the
remainder proof go through.

And the tag can be blinded. Each transfer publishes H = A_a h^gamma with a fresh
gamma and does its range proofs against H, so two settlements in the same asset
look no more alike than two settlements in different ones. The binding to the
real asset is not lost: the remainder proof has to open against the payer's
existing balance, which is already committed under A_a, and no other tag will
satisfy it.

What still needs a proof is *issuance*. Anyone can invent a point and call it an
asset, so opening an account with a non-zero balance carries a one-out-of-many
proof that its tag is one of the registered ones. That cost is paid once per
account, not once per settlement.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from zk.commit import Pedersen
from zk.gk_oneofmany import GkProof, GkProver, GkVerifier
from zk.groups import Group

ASSET_DOMAIN = b"qomm:defmi:asset:"


def asset_tag(group: Group, asset_id: int):
    """The generator that carries units of this asset."""
    return group.hash_to_point(ASSET_DOMAIN + asset_id.to_bytes(4, "big"))


@dataclass(frozen=True)
class BlindedTag:
    """A per-transfer disguise for an asset generator."""

    point: Any
    membership: GkProof | None = None

    def key_for(self, key: Pedersen) -> Pedersen:
        return key.with_value_generator(self.point)


class AssetRegistry:
    """The public list of tradeable assets, padded to a power of two.

    Padding is not bookkeeping: the one-out-of-many proof needs a power-of-two
    set, and a set that grew whenever a new asset was listed would leak the
    listing.
    """

    def __init__(self, group: Group, key: Pedersen, count: int):
        if count < 1:
            raise ValueError("a registry needs at least one asset")
        self.group = group
        self.key = key
        self.count = count
        self.size = 1 << max(1, (count - 1).bit_length())
        # padding entries are real points, so a verifier cannot tell them apart
        self.tags = [asset_tag(group, i) for i in range(self.size)]
        self._prover = GkProver(group, key)
        self._verifier = GkVerifier(group, key)

    def blind(self, asset_id: int, *, prove: bool = False) -> tuple[BlindedTag, int]:
        """H = A h^gamma, optionally with the proof that A is on the list."""
        if not 0 <= asset_id < self.count:
            raise ValueError(f"asset {asset_id} is not registered")
        gamma = self.key.random_blinding()
        point = self.group.mul(self.tags[asset_id],
                               self.group.point_pow(self.key.h, gamma))
        membership = None
        if prove:
            membership = self._prover.prove(self._quotients(point), asset_id, gamma)
        return BlindedTag(point, membership), gamma

    def _quotients(self, point) -> list:
        """H / A_i, which is h^gamma at exactly the registered index."""
        group = self.group
        return [group.mul(point, group.neg(tag)) for tag in self.tags]

    def verify_membership(self, tag: BlindedTag) -> bool:
        if tag.membership is None:
            return False
        return self._verifier.verify(self._quotients(tag.point), tag.membership)

    def unblinded(self, asset_id: int) -> BlindedTag:
        """The tag used for a balance that is held rather than moved."""
        return BlindedTag(self.tags[asset_id])
