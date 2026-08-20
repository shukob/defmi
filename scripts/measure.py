"""One way of reporting a repeated measurement, used by every runner.

A bare median says what one number came out and nothing about whether it means
anything. Two runs of the same benchmark on this machine have disagreed by half
again, and a reader --- including a later version of us --- cannot tell that from
a single figure. So every timing here carries how many samples it is made of and
how far they spread.

Both a mean and a median are kept, deliberately. Timings are right-skewed: one
scheduling hiccup pulls the mean and leaves the median alone, so the median is
what to compare and the mean is what the standard deviation belongs to. When the
two disagree by much, that is itself the finding.

Deterministic quantities do not go through this. A compiler's round count, a
proof's byte length and a state root are the same on every run, and dressing
them with a standard deviation of zero would claim a measurement nobody made.
Those stay exact, and `exact()` marks them as such so the two kinds cannot be
confused downstream.
"""

from __future__ import annotations

import statistics
from typing import Iterable, Sequence


def summarise(samples: Sequence[float] | Iterable[float]) -> dict:
    """`{n, mean, sd, median, min, max, rsd}` for a set of repeated timings.

    `sd` is the sample standard deviation and is `None` for a single sample,
    because one observation has no spread --- reporting zero there would say the
    measurement was stable when it was never repeated. `rsd` is the spread as a
    fraction of the mean, which is the form worth glancing at: anything above a
    few percent means the last digit of the mean is not real.
    """
    values = [float(v) for v in samples]
    if not values:
        return {"n": 0, "mean": None, "sd": None, "median": None,
                "min": None, "max": None, "rsd": None}
    mean = statistics.fmean(values)
    sd = statistics.stdev(values) if len(values) > 1 else None
    return {
        "n": len(values),
        "mean": mean,
        "sd": sd,
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
        "rsd": (sd / mean) if sd is not None and mean else None,
    }


def exact(value: float | int) -> dict:
    """A quantity that is identical on every run, marked as such.

    Round counts, byte lengths and proof sizes are functions of the program, not
    of the machine. Passing them through `summarise` would produce a standard
    deviation of zero that looks like a measurement and is not one.
    """
    return {"exact": value}


def render(summary, places: int = 2, unit: str = "") -> str:
    """`mean ± sd (n=N)` for a console line. The artifact keeps the full record.

    A bare number is accepted and rendered without a spread, for the same reason
    `value` accepts one: artifacts are converted one runner at a time, and a
    reader should keep working against the ones that have not been. What it must
    not do is invent a spread for a number that never carried one.
    """
    if isinstance(summary, (int, float)):
        return f"{float(summary):.{places}f}{unit}"
    if "exact" in summary:
        return f"{summary['exact']}{unit} (exact)"
    if summary["n"] == 0:
        return "—"
    if summary["sd"] is None:
        return f"{summary['mean']:.{places}f}{unit} (n=1)"
    return (f"{summary['mean']:.{places}f} ± {summary['sd']:.{places}f}{unit} "
            f"(n={summary['n']})")


def scaled(summary: dict, factor: float) -> dict:
    """The same measurement in another unit.

    Only the quantities that carry the unit are multiplied. `n` is a count and
    `rsd` is a ratio, so both are left alone --- scaling them was the bug this
    exists to stop, and it is invisible in output because `render` does not
    print `rsd`.
    """
    if "exact" in summary:
        return {"exact": summary["exact"] * factor}
    out = dict(summary)
    for key in ("mean", "sd", "median", "min", "max"):
        if out.get(key) is not None:
            out[key] = out[key] * factor
    return out


def value(summary) -> float | None:
    """The single number to quote where only one fits.

    The mean, because that is what the standard deviation beside it describes.
    Accepts a bare float so a consumer can be updated after its producer, and an
    `exact` record so deterministic quantities read the same way.
    """
    if isinstance(summary, (int, float)):
        return float(summary)
    if not isinstance(summary, dict):
        return None
    if "exact" in summary:
        return float(summary["exact"])
    return summary.get("mean")


def spread(summary) -> tuple[float | None, int]:
    """`(sd, n)` for a summary, or `(None, 1)` for anything that is not one."""
    if not isinstance(summary, dict) or "exact" in summary:
        return None, 1
    return summary.get("sd"), summary.get("n", 1)
