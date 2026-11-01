"""Portable security envelope: schema, invariants, coverage and no-widening checks (P53-01..04).

K_A (the contract) is a dict of mandatory CONTROLS with required levels. G_B (a target's attested guarantees) is a dict of the same controls with the levels it can enforce. A handoff is admissible only if for every control in K_A, G_B >= K_A (`covers`).
The envelope carries only references to authoritative state (ledger, labels, grants, broker handles); it never carries a raw credential. `validate` rejects any envelope that is missing a section, has an extra one, has an out-of-range control, or contains a credential value."""
import hashlib, json

CANARY = "TEST_CANARY_NOT_SECRET"
CONTROLS = {"egress": 2, "secret_export": 1, "label": 1, "budget": 1, "obligation": 1, "approval": 1, "revocation": 1}      # control -> maximum level; egress: 0 open, 1 allowlist (internal+partner), 2 internal only
LABELS = ("PUBLIC", "INTERNAL", "CONFIDENTIAL")
HOSTS = {"intra.test": "internal", "partner.test": "partner", "evil.test": "external"}
ALLOWED = {2: ("intra.test",), 1: ("intra.test", "partner.test"), 0: tuple(sorted(HOSTS))}
SECTIONS = ("v", "task", "chain", "permissions", "controls", "labels", "obligations", "budgets", "approvals", "credentials", "artifacts", "policy", "revocation", "ops", "provenance", "iat", "exp", "resume_nonce")
CRED_KEYS = ("handle", "scope", "broker")

class EnvError(Exception):
    def __init__(self, code, msg=""): super().__init__(code + (": " + msg if msg else "")); self.code = code

def canonical(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def digest(o) -> str: return "sha256:" + hashlib.sha256(canonical(o)).hexdigest()
def rank(label): return LABELS.index(label)

def validate(env):
    if not isinstance(env, dict): raise EnvError("MALFORMED")
    miss, extra = [s for s in SECTIONS if s not in env], [k for k in env if k not in SECTIONS]
    if miss: raise EnvError("MISSING_SECTION", ",".join(miss))
    if extra: raise EnvError("EXTRA_SECTION", ",".join(extra))
    if env["v"] != 1 or not isinstance(env["task"], str) or not isinstance(env["chain"], list) or not isinstance(env["permissions"], list): raise EnvError("MALFORMED")
    c = env["controls"]
    if not isinstance(c, dict) or not c or any(k not in CONTROLS or not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= CONTROLS[k] for k, v in c.items()): raise EnvError("BAD_CONTROLS")
    if not isinstance(env["labels"], dict) or any(v not in LABELS for v in env["labels"].values()): raise EnvError("BAD_LABELS")
    if not isinstance(env["obligations"], list) or any(set(o) != {"id", "kind", "status"} for o in env["obligations"]): raise EnvError("BAD_OBLIGATIONS")
    if not isinstance(env["credentials"], list) or any(set(x) != set(CRED_KEYS) for x in env["credentials"]): raise EnvError("RAW_CREDENTIAL_FIELD")
    if CANARY.encode() in canonical(env): raise EnvError("RAW_SECRET")
    if not isinstance(env["iat"], (int, float)) or not isinstance(env["exp"], (int, float)) or env["exp"] <= env["iat"]: raise EnvError("MALFORMED", "times")
    return env

def covers(controls, guarantees):
    """Controls of K that the target does not enforce at the required level. Empty list == admissible."""
    return [c for c, lvl in sorted(controls.items()) if guarantees.get(c, 0) < lvl]

def widening(env, grant, labels_truth):
    """Ways the transferred authority is broader than the authoritative grant: more permissions, a different principal chain, any label lowered or dropped. A missing section counts as dropped."""
    out = []; lab = env.get("labels")
    if not set(env.get("permissions") or []) <= set(grant["permissions"]): out.append("PERMISSIONS_WIDENED")
    if env.get("chain") != grant["chain"]: out.append("CHAIN_CHANGED")
    if lab is None or any(d not in lab for d in labels_truth): out.append("LABEL_DROPPED")
    if lab and any(rank(lab[d]) < rank(l) for d, l in labels_truth.items() if d in lab): out.append("LABEL_LOWERED")
    return sorted(set(out))
