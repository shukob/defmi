"""Agreeing with the book of record without opening anything to it.

**The Rust port in `rust/qomm-defmi/src/reconcile.rs` is the one to read.** It
is where the per-position check became a batch --- one multiscalar rather than a
commitment a position, 23.6 ms against 318 ms over 4,096 --- and where the
aggregate stopped paying a scalar multiplication to multiply by one. This file
keeps the shape of the argument and the measurement the first table was taken
against.

Under Japan's book-entry regime DeFMI cannot *be* the register: title rests on
the record the transfer agent and the account management institutions keep, so
this ledger is a mirror and reconciliation is not a feature but the price of
that arrangement --- `COMPLIANCE_JA.md` section 3.2 takes that position and this
is the machinery for it. The same shape fits a bank's core ledger holding one
omnibus balance, or a custodian's customer account, or anything else that holds
a number this ledger holds a distribution of.

**The whole mechanism is one line of algebra.** Balances are commitments, and
commitments multiply:

    prod_i C_i  =  A_a^{sum_i v_i} . h^{sum_i r_i}

The register says the account holds `N`. Divide `A_a^N` out of the product and
what is left must be a pure power of `h`; proving knowledge of that exponent
proves `sum v_i = N` and says nothing else. No individual balance opens, and `N`
was the register's own number, so **the proof discloses nothing that was not
already on both sides**. `zk.commit.prove_linear` is exactly this proof with the
coefficients all one, so nothing new is being invented here either.

Three things follow that are worth stating before the code.

**Nobody holds the aggregate blinding.** Each holder has its own `r_i`. Either
the account management institution holds them --- it already holds the mapping
from handle to book-entry account, so it is the party that can --- or a quorum
assembles the proof without reconstructing the sum, which is what
`zk/threshold_sigma.py` does and why `prove_by_quorum` exists.

**A break is pass or fail and nothing more.** If the totals disagree the proof
cannot be produced, and that is all anyone learns. Finding *where* they disagree
means opening subtotals, and every subtotal opened is disclosure that the design
otherwise refuses. `locate_break` bisects, so it costs about `log2(n)` subtotals
--- and it reports how many it opened, because the number is the price.

**The note rail needs no special case.** A note publishes its value commitment
separately from its one-time point, so the product over the unspent notes has
the same shape as the product over accounts, and the same proof serves. What it
cannot do is reconcile one *holder*: there are no accounts to sum over, so a
per-holder figure needs the holder, or its view key, to enumerate its own notes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from zk.commit import OpeningProof, Pedersen, prove_linear, verify_linear
from zk.groups import Group

RECONCILE_DOMAIN = b"QOMM:DEFMI:RECONCILE:v1"


@dataclass(frozen=True)
class Attestation:
    """What the authoritative ledger says, and who said it.

    Carried rather than passed loose because reconciling against a number
    somebody typed is not reconciling. The signature is optional here and is not
    optional in a deployment: without one the check says the ledger agrees with
    whatever it was handed.
    """

    register: str            # which book of record
    account: str             # the account there
    asset: str               # its name for the instrument
    total: int               # the figure it holds
    as_of: str               # its own timestamp, verbatim
    signature: bytes = b""

    def body(self) -> bytes:
        return hashlib.sha256(
            RECONCILE_DOMAIN
            + b"".join(len(part).to_bytes(4, "big") + part for part in (
                self.register.encode(), self.account.encode(),
                self.asset.encode(), self.as_of.encode()))
            + self.total.to_bytes(16, "big", signed=True)).digest()


@dataclass(frozen=True)
class Reconciliation:
    """One statement that a set of committed balances sums to a stated total."""

    attestation: Attestation
    positions: int
    proof: OpeningProof
    quorum: tuple[int, ...] = ()
    transcript: Mapping[str, Any] = field(default_factory=dict)


def context_of(attestation: Attestation) -> bytes:
    return RECONCILE_DOMAIN + b":" + attestation.body()


def aggregate(group: Group, commitments: Sequence[Any]):
    """The product, which is a commitment to the sum by construction."""
    total = group.identity()
    for commitment in commitments:
        total = group.mul(total, commitment)
    return total


def prove(key: Pedersen, commitments: Sequence[Any], blindings: Sequence[int],
          attestation: Attestation) -> Reconciliation:
    """Show the committed balances sum to the register's figure.

    `key` must carry the asset tag the balances are committed under; a
    base-generator key would divide the total out under the wrong generator and
    the proof simply would not verify, which is the right failure.
    """
    if len(commitments) != len(blindings):
        raise ValueError("a blinding per commitment, or the sum is not the sum")
    proof = prove_linear(key, list(blindings), [1] * len(blindings),
                         context=context_of(attestation),
                         commitments=list(commitments),
                         constant=attestation.total)
    return Reconciliation(attestation=attestation, positions=len(commitments),
                          proof=proof)


def check(key: Pedersen, commitments: Sequence[Any],
          reconciliation: Reconciliation,
          registrar=None) -> tuple[bool, str]:
    """Whether this ledger agrees with the register, and why not when it does not."""
    if len(commitments) != reconciliation.positions:
        return False, (f"reconciliation covers {reconciliation.positions} "
                       f"positions and {len(commitments)} were offered")
    attestation = reconciliation.attestation
    if registrar is not None:
        from cryptography.exceptions import InvalidSignature

        try:
            registrar.verify(attestation.signature, attestation.body())
        except (InvalidSignature, ValueError):
            return False, "the attestation is not signed by that registrar"
    elif attestation.signature:
        return False, ("an attestation carries a signature and no registrar key "
                       "was given to check it against")
    ok = verify_linear(key, list(commitments), [1] * len(commitments),
                       attestation.total, reconciliation.proof,
                       context=context_of(attestation))
    if not ok:
        return False, (f"the committed balances do not sum to "
                       f"{attestation.total}: a break, and this says nothing "
                       f"about where")
    return True, ""


# --- when nobody holds the aggregate blinding -----------------------------

def prove_by_quorum(key: Pedersen, commitments: Sequence[Any], shares,
                    quorum: Sequence[int],
                    attestation: Attestation) -> Reconciliation:
    """The same statement, assembled by nodes that hold shares of the blinding.

    `shares` is a `zk.threshold_sigma.ShareSet` over the aggregate blinding. The
    sigma response is affine in the witness, so the quorum's partials combine
    into one ordinary proof and no node ever holds the sum --- which is the
    point, because the sum is what would let its holder open the whole ledger.
    """
    from zk.threshold_sigma import joint_prove_opening

    group = key.group
    residual = group.mul(aggregate(group, commitments),
                         group.neg(key.commit(attestation.total % group.order, 0)))
    if group.encode(residual) != group.encode(shares.commitment):
        raise ValueError("the shared blinding is not the one these commitments "
                         "and this total leave behind")
    proof, transcript = joint_prove_opening(key, shares, quorum,
                                            context=context_of(attestation))
    return Reconciliation(attestation=attestation, positions=len(commitments),
                          proof=proof, quorum=tuple(quorum),
                          transcript=transcript)


# --- when the register holds a figure per position ------------------------

def check_positions(key: Pedersen, commitments: Sequence[Any],
                    blindings: Sequence[int],
                    expected: Sequence[int]) -> list[int]:
    """Which positions do not hold what the register says they hold.

    The level above `prove`: an account management institution holds a figure
    per customer, not one figure for the account, so it can reconcile position
    by position and a break localises for free. It needs the openings, which is
    exactly the party that has them --- it is already the party holding the
    mapping from handle to book-entry account.

    Nothing is disclosed to anybody else by running this. It is arithmetic on
    numbers the runner already holds.
    """
    group = key.group
    return [i for i, (commitment, blinding, value)
            in enumerate(zip(commitments, blindings, expected))
            if group.encode(key.commit(value, blinding)) != group.encode(commitment)]


# --- finding a break when the register holds only a total -----------------

@dataclass
class BreakSearch:
    """Where the disagreement is, and how much became public in finding it."""

    found: list[int] = field(default_factory=list)
    proofs: int = 0
    ranges_made_public: list[tuple[int, int, int]] = field(default_factory=list)

    @property
    def cost(self) -> str:
        return (f"{self.proofs} sub-range proofs; "
                f"{len(self.ranges_made_public)} sub-totals now public, "
                f"the narrowest covering "
                f"{min((h - l for l, h, _ in self.ranges_made_public), default=0)} "
                f"positions")


def locate_break(key: Pedersen, commitments: Sequence[Any],
                 blindings: Sequence[int], claimed, expected: int) -> BreakSearch:
    """Bisect to the positions that do not add up, one sub-proof per step.

    `claimed(low, high) -> int` is the register answering "what should positions
    `[low, high)` total". A register that holds only one figure cannot answer it,
    and then a break stays pass-or-fail: **there is nothing here that finds a
    break without somebody claiming subtotals**, and pretending otherwise would
    be the useful-looking lie in this module.

    What it costs is the point. Each step publishes a sub-total, and a sub-total
    over one position is a balance. About `2*log2(n)` steps for a single break,
    closer to `n` for a ledger with many. The search records every range it made
    public so the cost is reported rather than absorbed.
    """
    search = BreakSearch()
    if not commitments:
        return search

    def holds(low: int, high: int, total: int) -> bool:
        attestation = Attestation(register="sub-range", account=f"[{low},{high})",
                                  asset="", total=total, as_of="")
        proof = prove(key, list(commitments[low:high]), list(blindings[low:high]),
                      attestation)
        search.proofs += 1
        ok, _ = check(key, list(commitments[low:high]), proof)
        return ok

    def descend(low: int, high: int, total: int) -> None:
        search.ranges_made_public.append((low, high, total))
        if holds(low, high, total):
            return
        if high - low == 1:
            search.found.append(low)
            return
        middle = (low + high) // 2
        descend(low, middle, claimed(low, middle))
        descend(middle, high, claimed(middle, high))

    descend(0, len(commitments), expected)
    return search
