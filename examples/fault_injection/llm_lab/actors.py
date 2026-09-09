"""Who decides what an agent does.

Every experiment here has exactly one point where an agent's action is
CHOSEN. Nothing downstream -- authority, argument policy, correlation,
containment, evidence, the verifiers, the invariants -- ever asks who chose
it. That seam is this module.

    ScriptedActor   deterministic tables; the default, and the one the
                    sabotage suites run against
    LLMActor        a real model deciding, through the same interface
    ReplayActor     recorded model decisions, replayed deterministically

Keeping them behind one interface is what lets stage 1 and stage 2 be the
same experiment rather than two: stage 1 varies the MECHANISMS with the
actor held deterministic; stage 2 varies the ACTOR with the mechanisms and
the measurement apparatus held fixed.

The scripted actor is also the regression oracle. A mechanism-removal
mutation that stops being caught after a change to this seam means the
change broke the apparatus -- which is discoverable offline, for free,
before a single API call.
"""
from __future__ import annotations

from typing import NamedTuple


class Situation(NamedTuple):
    """Everything an actor is told before it decides.

    `hint` carries the experiment's own scripted resolution. A model-backed
    actor ignores it; the scripted actor is nothing but it.
    """
    principal: str
    role: str
    step: int
    kind: str = "normal"          # "normal" | "injected"
    instructions: tuple = ()      # e.g. taints this agent has absorbed
    # Who sent them. Naming the sender is part of the social situation the
    # relay wording models, and it was being replaced with "another agent"
    # at the prompt even though the experiment knew.
    sender: str | None = None
    tools: tuple = ()             # what it may call
    hint: dict | None = None      # the deterministic answer, if there is one
    # The agent's LEGITIMATE job, which is not the same thing as the hint
    # on an injected step. Describing the fault as the agent's own task
    # made compliance unmeasurable: the model was told to do the harmful
    # thing twice, once with authority, and "refusal" could then only mean
    # refusing its own work.
    task: dict | None = None
    # The planted instruction, present only in the treatment arm. Separate
    # from `hint` on purpose: `hint` is what COMPLIANCE looks like, and an
    # actor that could only return the hint could not refuse.
    injected_instruction: dict | None = None


class Actor:
    """Chooses the tool call an agent makes at one step."""

    name = "actor"
    deterministic = True

    def act(self, situation: Situation) -> dict:
        raise NotImplementedError

    def describe(self) -> dict:
        """Goes into provenance. Must never carry a credential."""
        return {"actor": self.name, "deterministic": self.deterministic}


class ScriptedActor(Actor):
    """The deterministic behaviour the experiments were validated against.

    It returns the experiment's own answer unchanged. This is the default
    everywhere, so `--check`, `--sweep` and every sabotage script stay
    offline, free and reproducible.
    """

    name = "scripted"
    deterministic = True

    def act(self, situation: Situation) -> dict:
        if situation.hint is None:
            raise ValueError(
                f"no scripted action for {situation.principal}/"
                f"{situation.role} at step {situation.step}")
        return dict(situation.hint)


_DEFAULT = ScriptedActor()


def resolve(actor: Actor | None, situation: Situation) -> dict:
    """Call `actor`, falling back to the scripted one.

    A `None` actor routes through ScriptedActor rather than reading the
    hint inline, so the default path is the same code the sabotage suites
    exercise -- and so a missing hint raises where it happens instead of
    yielding `{}` and failing later with a KeyError on `payload["tool"]`.
    """
    return (actor or _DEFAULT).act(situation)
