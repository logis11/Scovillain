"""A discriminator must discriminate — the project's third structural guard.

## Where this came from (2026-10-17/18, measured twice in one day)

The first two guards in this project are about *control flow*: a `REFUTED` needs
an empty frontier (`verdict/contract.py`), and a pairing asymmetry needs its
modulus (`query/pairing.py`). This one is about *attributes*: the moment a
verdict leans on "I read field X and it said V", the read can be correct, the
byte can be real, and the claim can still be empty.

The incident: a driver's feature gate was read from one byte of a WIL feature
descriptor and reported as "default ON", which was then used to close a finding
as unreportable. Re-measured across the whole descriptor population, that byte
held the **same value in 38 of 38 descriptors** — it discriminated nothing. In a
second image it was constant across all 6. A different byte did vary, and the
analyst session months earlier had seen exactly that and *refused to confirm*.

Then, fixing it, the same error recurred one level down: the first fix accepted
**any** varying offset as a discriminator — including pointer and id fields,
which of course differ per member. Variance is necessary, not sufficient: the
field also has to be of a kind that can *encode a state*.

So the rule has two teeth, and both are mechanical:

    1. A value that does not VARY across the population it was read from cannot
       support a claim about a member of that population.
    2. A field that varies with high cardinality or large values is an identity
       (pointer / id / hash), not a state. It cannot support a state claim either.

And one thing the guard cannot give you: even a well-behaved enum tells you only
**who is unusual**, never **what the state is**. Mapping a value to a meaning
needs a labelled member (here: features named `*Servicing*`, i.e. shipped
fixes). Without a label, "matches the majority" is `UNSETTLED`, not "enabled" —
calling it "enabled" is the original error with extra steps.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum

from scovillain.verdict.contract import Answer, unknown


class FieldKind(str, Enum):
    CONSTANT = "constant"    # one value across the population -> no information
    ENUM = "enum"            # few small values -> can encode a state
    IDENTITY = "identity"    # high cardinality / large values -> pointer or id

    @property
    def can_carry_state(self) -> bool:
        return self is FieldKind.ENUM


@dataclass(frozen=True)
class FieldPopulation:
    """The values one field takes across every member of a population.

    `members` is parallel to `values` so a caller can say *which* member is the
    outlier, which is the only thing a population can actually tell you.
    """
    name: str
    values: tuple
    members: tuple = ()
    max_enum_card: int = 4
    max_enum_value: int = 0x10

    @property
    def counts(self) -> Counter:
        return Counter(self.values)

    @property
    def kind(self) -> FieldKind:
        c = self.counts
        if len(c) <= 1:
            return FieldKind.CONSTANT
        if len(c) <= self.max_enum_card:
            # The magnitude test only applies to numbers: a raw byte with a huge
            # value is an address, but a categorical label (an enum member, a
            # verdict name) is already a state and has no magnitude.
            ints = [v for v in c if isinstance(v, int) and not isinstance(v, bool)]
            if not ints or max(ints) <= self.max_enum_value:
                return FieldKind.ENUM
        return FieldKind.IDENTITY

    @property
    def discriminates(self) -> bool:
        return self.kind.can_carry_state

    def refusal(self) -> str:
        """Why this field cannot support a state claim, or '' if it can."""
        if self.kind is FieldKind.CONSTANT:
            return ("field %r holds a single value (%r) across all %d members: it "
                    "discriminates nothing, so no claim about any member can rest "
                    "on it" % (self.name, self.values[0] if self.values else None,
                               len(self.values)))
        if self.kind is FieldKind.IDENTITY:
            return ("field %r varies with %d distinct values across %d members: that "
                    "is an identity (pointer/id), not a state — variance alone is "
                    "not discriminating power" % (self.name, len(self.counts),
                                                  len(self.values)))
        return ""

    def outliers(self) -> list[tuple]:
        """[(member, value, majority)] for members in the minority. This is the
        ONLY positive statement a population supports without a labelled member."""
        if not self.discriminates:
            return []
        maj = self.counts.most_common(1)[0][0]
        out = []
        for i, v in enumerate(self.values):
            if v != maj:
                out.append((self.members[i] if i < len(self.members) else i, v, maj))
        return out


def require_discriminating(pop: FieldPopulation, source: int = 0,
                           sink: int = 0, **anchor) -> Answer | None:
    """Gate for any rule about to decide something from `pop`.

    Returns `None` when the field may be used, or an `UNKNOWN` Answer carrying
    the reason when it may not. `UNKNOWN` (not `REFUTED`) is deliberate: a safe
    caller treats UNKNOWN as NOT_REFUTED, so an undiscriminating field can never
    delete a candidate.
    """
    why = pop.refusal()
    if not why:
        return None
    return unknown("undiscriminating field: " + why, source=source, sink=sink, **anchor)
