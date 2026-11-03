"""Idea 4: causal sink diffing. Run the same workflow with and without a candidate control against FIXTURE-OWNED sink journals and attribute the difference to the control.
A control that LOGS 'blocked' but leaves the sink journal unchanged is flagged (claims_without_effect). The control's own log is never used as evidence of effect."""
from __future__ import annotations


def journal_of(workflow, control, make_sinks):
    sinks = make_sinks(); log = workflow(sinks, control); return sorted(sinks.rows), list(log or [])


def diff(workflow, control, make_sinks) -> dict:
    off, _ = journal_of(workflow, None, make_sinks); on, claims = journal_of(workflow, control, make_sinks)
    removed = [r for r in off if r not in on]; added = [r for r in on if r not in off]
    claimed = [c for c in claims if c.startswith("blocked:")]
    return {"removed_by_control": removed, "added_by_control": added, "control_effective": bool(removed), "side_effects_added": bool(added),
            "claims_without_effect": [c for c in claimed if not any(c.split(":", 1)[1] == r[1] for r in removed)], "baseline_effects": len(off)}


class Rows:
    def __init__(self): self.rows = []
    def write(self, sink, tag): self.rows.append((sink, tag))
