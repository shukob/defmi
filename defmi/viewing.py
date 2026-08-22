"""Handing an auditor one slice of a wallet, and being honest about what that is.

**The Rust port in `rust/qomm-defmi/src/viewing.rs` is the one to read.** It
adds the join this file does not have: a scope's notes come back as
commitments, so a scope can be reconciled against a figure an auditor was given
without opening a single note.

`notes.py` splits a wallet into a view key and a spend key and says the view key
"could be handed to an auditor". It could, and that is all it could: the key is
one key, so handing it over gives the whole history of that wallet, in every
instrument, for every period, permanently. There is no scope and no way back.

The scoping does not go in the key. It goes in the **address**. A wallet is a
pair of seeds; a scope --- an instrument, a quarter, a mandate, whatever the
grant is about --- derives a fresh pair of scalars by hashing, and therefore a
fresh address. Notes sent to that address are found by that scope's view key and
by nothing else, and the derivation is one way, so a scope's key says nothing
about the seed or about a sibling scope.

    view_s  = H("view"  || seed_v || scope)      the auditor gets this
    spend_s = H("spend" || seed_s || scope)      it does not
    address = (g^{view_s}, g^{spend_s})          both halves are public

Nothing here is new cryptography and that is deliberate: the note construction
is unchanged, the scan is unchanged, and what changes is which address a payer
is told to use. Which means it also works with a counterparty that has already
implemented the old thing.

**Three things it does not do, said here rather than found later.**

*A grant cannot be taken back.* Once someone holds `view_s` they can read every
note that was ever sent to that address and every note that ever will be. What
an expiry buys is that the wallet stops publishing that address after the
period, so nothing new lands there --- the cryptography does not un-see, and
`check_grant` refusing an expired grant binds only a party that chose to be
bound. Revocation is the *next* scope, not a message.

*A view key is incoming only.* It finds what arrived. It cannot see what the
wallet spent, because spending publishes a serial and a ring and neither is
derivable from the view key. An auditor that needs outflows needs the wallet to
hand over its serials, which is a different disclosure and is not this one.

*Scoping is only as fine as the payers cooperate.* A scope exists because
counterparties were told to pay to that address. A payer who uses last
quarter's address puts the note in last quarter's scope, and nothing in the
protocol stops them. That is an operational control wearing a cryptographic
coat, and it is worth knowing which it is.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from zk.commit import Pedersen
from zk.groups import Group

from .notes import Address, NoteLedger, Opening, Wallet

VIEW_DOMAIN = b"qomm:defmi:view:v1"


def derive(group: Group, seed: bytes, role: bytes, scope: str) -> int:
    """One scope's scalar. One way, so a scope reveals neither seed nor sibling."""
    digest = hashlib.sha512(VIEW_DOMAIN + b":" + role + b":")
    for part in (seed, scope.encode()):
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return int.from_bytes(digest.digest(), "big") % group.order


class ViewOnly:
    """What an auditor holds: enough to find notes, not enough to move them.

    The same surface `NoteLedger.scan` wants, minus the one method that turns a
    note into a serial number --- which is not withheld by policy but absent,
    because the scalar it needs was never derived here.
    """

    def __init__(self, group: Group, address: Address, view: int):
        self.group = group
        self.address = address
        self._view = view

    def shared(self, ephemeral) -> int:
        return _shared(self.group, ephemeral, self._view)

    def serial(self, ephemeral) -> int:
        raise PermissionError(
            "a view key cannot produce a serial number, which is what spending "
            "needs. This is the separation the grant is for.")

    @property
    def _spend(self) -> int:                       # what `scan` reaches for
        raise PermissionError("a view key holds no spend key")


def _shared(group: Group, ephemeral, view: int) -> int:
    from .notes import _scalar

    return _scalar(group, b"shared",
                   group.encode(group.point_pow(ephemeral, view)))


@dataclass(frozen=True)
class ViewingGrant:
    """One scope handed to one named party, signed by the wallet that owns it.

    The grantee is named and the grant is signed so that a key found somewhere
    it should not be can be traced to the grant that produced it. That is
    attribution, not prevention, and it is the same trade `roles.py` makes about
    dealt shares.
    """

    scope: str
    grantee: str
    address: Address
    view_key: int
    issued_at: int
    expires_at: int
    signature: bytes = b""

    def body(self, group: Group) -> bytes:
        return hashlib.sha256(
            VIEW_DOMAIN + b":grant:"
            + b"".join(len(p).to_bytes(4, "big") + p for p in (
                self.scope.encode(), self.grantee.encode(),
                group.encode(self.address.view), group.encode(self.address.spend)))
            + self.issued_at.to_bytes(8, "big")
            + self.expires_at.to_bytes(8, "big")).digest()

    def viewer(self, group: Group) -> ViewOnly:
        return ViewOnly(group, self.address, self.view_key)


class ScopedWallet:
    """A wallet that can hand out one slice of itself at a time.

    The seeds never leave. A scope is derived from them, so the wallet can
    reproduce any scope it has ever granted --- which is what lets it keep
    spending notes it has given an auditor the ability to read.
    """

    def __init__(self, group: Group, view_seed: bytes | None = None,
                 spend_seed: bytes | None = None,
                 identity: Ed25519PrivateKey | None = None):
        import secrets

        self.group = group
        self.view_seed = view_seed or secrets.token_bytes(32)
        self.spend_seed = spend_seed or secrets.token_bytes(32)
        self.identity = identity or Ed25519PrivateKey.generate()

    @property
    def public_identity(self) -> Ed25519PublicKey:
        return self.identity.public_key()

    def wallet(self, scope: str) -> Wallet:
        """The full wallet for one scope. This is what spends."""
        return Wallet(self.group,
                      view=derive(self.group, self.view_seed, b"view", scope),
                      spend=derive(self.group, self.spend_seed, b"spend", scope))

    def address(self, scope: str) -> Address:
        return self.wallet(scope).address

    def grant(self, scope: str, grantee: str, *, issued_at: int | None = None,
              days: int = 90) -> ViewingGrant:
        """Hand out the ability to read one scope, and sign that it was handed out."""
        issued = int(time.time()) if issued_at is None else issued_at
        grant = ViewingGrant(
            scope=scope, grantee=grantee, address=self.address(scope),
            view_key=derive(self.group, self.view_seed, b"view", scope),
            issued_at=issued, expires_at=issued + days * 86_400)
        return ViewingGrant(**{**grant.__dict__,
                               "signature": self.identity.sign(grant.body(self.group))})


def check_grant(group: Group, grant: ViewingGrant, owner: Ed25519PublicKey,
                now: int | None = None) -> tuple[bool, str]:
    """Whether this grant is what it says, and still current.

    Current is a statement about policy and not about capability. A party that
    holds the key can read whatever the key reads whether or not this returns
    True; what refusing buys is that a party which *wants* to stay inside its
    mandate has something to check against, and that a party which does not can
    be shown to have gone outside it.
    """
    if not grant.signature:
        return False, "an unsigned grant is a key somebody wrote down"
    try:
        owner.verify(grant.signature, grant.body(group))
    except (InvalidSignature, ValueError):
        return False, "not signed by that wallet"
    if group.encode(group.base_pow(grant.view_key)) != group.encode(grant.address.view):
        return False, "the key does not open the address it names"
    at = int(time.time()) if now is None else now
    if at < grant.issued_at:
        return False, "the grant has not begun"
    if at >= grant.expires_at:
        return False, ("the grant has expired --- which stops a party that "
                       "chooses to be stopped, and nothing else")
    return True, ""


def scan_scope(ledger: NoteLedger, viewer: ViewOnly,
               asset_key: Pedersen) -> Mapping[int, Opening]:
    """Every note in the pool addressed to this scope, and their amounts.

    The serial is not recovered --- it needs the spend key --- so the openings
    returned carry `-1` in that field, the same sentinel `build_note` uses for
    a note whose serial its sender cannot know.
    """
    group = ledger.group
    found: dict[int, Opening] = {}
    for index, note in enumerate(ledger.notes):
        shared = viewer.shared(note.ephemeral)
        masks = ledger._masks(shared)
        value = (note.masked_value - masks[0]) % group.order
        blinding = (note.masked_blinding - masks[1]) % group.order
        if value > ledger.max_value:
            continue
        expected = group.mul(ledger.one_time_point(viewer.address, shared),
                             asset_key.commit(value, blinding))
        if group.encode(expected) == group.encode(ledger.commitment_of(note)):
            found[index] = Opening(value, blinding, serial=-1)
    return found


def total_seen(openings: Mapping[int, Opening]) -> int:
    """What the scope holds, for an auditor that has to put a number in a report."""
    return sum(opening.value for opening in openings.values())
