"""Stable labels for the machines the measurements were taken on.

Real host names identify people and networks, and every artifact used to carry
one because `platform.node()` is what the harnesses record. Keeping the real
name and scrubbing at publication time was the first plan, and it is the wrong
shape: it leaves a repository that is unsafe to publish until someone remembers
a step. So the label is applied where the name is recorded instead.

Putting the mapping *in this file* was the second mistake and the same one a
level down. The mapping is the provenance and is worth keeping --- but this
file ships, so keeping it here meant publishing exactly the names the labels
exist to withhold, and it did, from the first commit. The table now lives in
`scripts/host_map.txt`, which is not exported. When it is absent every machine
keeps its own name, which is what a reader of the published repository gets and
is the right answer for them: they have no reason to want our labels.

`scripts/export_repos.py` checks the export against this table and refuses to
write a name out, so the protection is a check rather than a habit.
"""

from __future__ import annotations

import os
from pathlib import Path

MAP_FILE = Path(__file__).resolve().parent / "host_map.txt"


def load(path: Path | None = None) -> dict[str, str]:
    """The mapping, or an empty one where the file does not exist.

    Absent is the normal case outside this working tree and is not an error:
    an unknown machine keeps its name, which is what `label` already does for
    every machine the table never held.
    """
    source = path or Path(os.environ.get("QOMM_HOST_MAP", MAP_FILE))
    try:
        text = source.read_text(encoding="utf-8")
    except OSError:
        return {}
    table: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, _, published = line.partition(" ")
        published = published.strip()
        if name and published:
            table[name] = published
    return table


LABELS = load()


def label(node: str) -> str:
    """The published name for a machine. Unknown machines keep their name."""
    return LABELS.get(node, LABELS.get(node.split(".")[0], node))


def this_host() -> str:
    """The label for the machine currently running, for harnesses to record."""
    import platform

    return label(platform.node())
