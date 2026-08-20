"""Stable labels for the machines the measurements were taken on.

Real host names identify people and networks, and every artifact used to carry
one because `platform.node()` is what the harnesses record. Keeping the real
name and scrubbing at publication time was the earlier plan, and it is the wrong
shape: it leaves a repository that is unsafe to publish until someone remembers
a step. The label is applied where the name is recorded instead, and this file
is the provenance --- nothing is lost that this mapping does not hold.
"""

from __future__ import annotations

LABELS = {
    "host-a": "host-a",       # 64 vCPU, RAM 234 GB, x86_64
    "host-a": "host-a",             # the ssh alias for the same machine
    "host-b": "host-b",             # 20 vCPU, RAM 62 GB, x86_64
    "host-b": "host-b",
    "host-c": "host-c",   # 14-inch laptop
}


def label(node: str) -> str:
    """The published name for a machine. Unknown machines keep their name."""
    return LABELS.get(node, LABELS.get(node.split(".")[0], node))


def this_host() -> str:
    """The label for the machine currently running, for harnesses to record."""
    import platform

    return label(platform.node())
