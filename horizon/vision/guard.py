"""HorizonVisionGuard decision (P51-03..07, 11, 15) and the compared baselines (P51-13).

A UI action is authorized only when (1) the browser can bind it to an object (else UNKNOWN), (2) that object is the one the agent meant (`bind_element`), (3) it lives in a frame the task trusts (`bind_frame`),
(4) its identity/effect has not changed since the agent observed it (`bind_version`), (5) the effect the BROWSER resolved is permitted for the task (`dest_policy`, `data_policy`), (6) the data being sent is what was
reviewed (`bind_input`), and (7) a protected effect carries a single-use APPROVAL from the shared HorizonPolicy authority bound to the exact envelope (`approval`).
Decisions: ALLOW / DENY / CONFIRM (a preflight for an approval is needed) / UNKNOWN (cannot bind; fail closed unless `fail_closed` is off). Modules never issue tokens; this module only verifies."""
from dataclasses import dataclass
from ..hpolicy.authority import EvidenceError
from . import core as C

@dataclass(frozen=True)
class GCfg:
    bind_element: bool = True; bind_frame: bool = True; bind_version: bool = True; derive_effect: bool = True; dest_policy: bool = True; data_policy: bool = True; bind_input: bool = True; approval: bool = True; fail_closed: bool = True
    script_unknown: bool = True                                             # an element whose effect is initiated by page script cannot be derived: UNKNOWN
    bind_approval: bool = True                                           # approval must match the envelope digest (else any valid token is accepted)

class Guard:
    def __init__(self, verifier, clock, cfg=GCfg(), principal="agent"): self.v, self.clock, self.cfg, self.principal = verifier, clock, cfg, principal
    def decide(self, act, b, task, token=None):
        c = self.cfg
        if b is None or not b.get("instrumented", False): return ("UNKNOWN" if c.fail_closed else "ALLOW"), "NO_TRUSTED_BINDING"
        eff = b["effect"] if c.derive_effect else (b["reported"] or {"kind": "NONE"})
        if c.bind_element and act.get("intent") is not None and act["intent"] != b["element"]["id"]: return "DENY", "ELEMENT_MISMATCH"
        kind = eff.get("kind", "NONE")
        if c.bind_frame and kind != "NONE" and b["frame_origin"] != b["top_origin"] and b["frame_origin"] not in task["frames"]: return "DENY", "CROSS_FRAME"
        if c.bind_version and act.get("observed") is not None and act["observed"] != b["element"]["digest"]: return "DENY", "STALE_ELEMENT"
        if c.script_unknown and b.get("script_handled"): return "UNKNOWN", "SCRIPT_HANDLED_EFFECT"
        if kind == "NONE": return "ALLOW", "NO_PROTECTED_EFFECT"
        if c.dest_policy and eff.get("dest") not in task["allowed"].get(kind, ()): return "DENY", "DEST_NOT_ALLOWED"
        if c.data_policy and eff.get("data") == "canary" and eff.get("dest") not in task["data_dest"]: return "DENY", "SENSITIVE_DATA_DEST"
        if c.bind_input and kind == "SUBMIT" and task.get("reviewed_input") is not None and b["input_digest"] != task["reviewed_input"]: return "DENY", "INPUT_CHANGED"
        if c.approval and kind in task["confirm"]:
            if token is None: return "CONFIRM", "APPROVAL_REQUIRED"
            try: p = self.v.verify(token, now=self.clock(), consume=True)
            except EvidenceError as e: return "DENY", "APPROVAL_" + e.code
            if p["kind"] != "APPROVAL": return "DENY", "APPROVAL_WRONG_KIND"
            if p["role"] != "approver": return "DENY", "APPROVAL_WRONG_ROLE"
            if c.bind_approval and p["args_digest"] != C.envelope_digest(C.envelope(act["op"], b["element"]["digest"], eff, b["input_digest"], b["top_origin"], b["tab"])): return "DENY", "APPROVAL_MISMATCH"
        return "ALLOW", "PERMITTED"

RISK = ("upload", "send", "delete", "pay", "transfer", "export", "submit", "download", "share", "confirm")
def _risky(t): t = (t or "").lower(); return any(w in t for w in RISK)

class Baseline:
    """Each baseline sees only what it would see: `b['visible']` (screenshot text under the point), `b['dom']` (DOM text / page-reported effect of the element the AGENT named), the page-reported or frame origin string, and the tool name."""
    def __init__(self, kind): self.kind = kind
    def decide(self, act, b, task, token=None):
        k = self.kind
        if k == "none": return "ALLOW", "NO_CONTROL"
        if k == "screenshot-filter": return ("DENY", "RISKY_VISIBLE_TEXT") if _risky(b and b.get("visible")) else ("ALLOW", "OK")
        if k == "dom-text": return ("DENY", "RISKY_DOM_TEXT") if _risky(b and b.get("dom")) or (b and (b.get("reported") or {}).get("kind", "NONE") in ("UPLOAD", "DOWNLOAD", "CLIPBOARD")) else ("ALLOW", "OK")
        if k == "safe-browsing": return ("DENY", "BLOCKLISTED") if b and ((b.get("reported") or {}).get("dest") in task["blocklist"] or b.get("frame_origin") in task["blocklist"]) else ("ALLOW", "OK")
        if k == "tool-allowlist": return ("DENY", "TOOL_NOT_ALLOWED") if act["op"] in ("tool_upload", "tool_download") else ("ALLOW", "OK")
        if k == "restrictive-rule":
            if b is None or not b.get("instrumented", False): return "UNKNOWN", "NO_TRUSTED_BINDING"
            e = b["effect"]
            if e["kind"] in ("UPLOAD", "DOWNLOAD", "CLIPBOARD"): return "DENY", "BLANKET_PROTECTED_SINK"
            if e["kind"] != "NONE" and (b["frame_origin"] != b["top_origin"] or e["dest"] != b["top_origin"]): return "DENY", "BLANKET_CROSS_ORIGIN"
            return "ALLOW", "OK"
        raise ValueError(k)
