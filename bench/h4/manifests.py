"""Versioned manifest schemas, manifest emission and the strict fixture lint (P37-01, P37-06). No scenario is described without an expectation, an oracle and a benign control."""
from __future__ import annotations
import json, os, re, hashlib
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
SCHEMA_VERSION = "1.0.0"; SCHEMA_ID = "horizon.bench.manifest.v1"
SUITES = {"HMIB": 20, "HCCB": 18, "HECB": 20, "HIEB": 16}
FIXTURE_KINDS = ("local_synthetic_inert",); KINDS = ("attack", "benign")
CONTROL = {"HMIB": "the approved model/adapter (untouched, exact pin) is deployed through the same pipeline and must load", "HCCB": "a patched, functionally-correct artifact with pinned dependencies is released through the same pipeline and must publish",
           "HECB": "an authorised same-tenant exchange / an honest run with only permitted operations must work and audit clean", "HIEB": "the hardened reference configuration is deployed and an authorised user must be served"}
def schema_for(suite: str) -> dict:
    return {"schema_dialect": "json-schema-2020-12 (structural subset)", "$id": f"{SCHEMA_ID}/{suite}", "title": f"{suite} scenario manifest", "schema_version": SCHEMA_VERSION, "type": "object", "additionalProperties": False,
            "required": ["benchmark_schema", "schema_version", "id", "suite", "scenario", "family", "kind", "fixture_kind", "summary", "requirements", "oracle", "expectation", "report", "benign_control", "stable_id_digest"],
            "properties": {"benchmark_schema": {"const": "horizon.incident.v1"}, "schema_version": {"const": SCHEMA_VERSION}, "id": {"type": "string", "pattern": f"^{suite}-[0-9]{{2}}$"}, "suite": {"const": suite}, "scenario": {"type": "string", "pattern": "^[a-z0-9_]+$"}, "family": {"type": "string"},
                           "kind": {"enum": list(KINDS)}, "fixture_kind": {"enum": list(FIXTURE_KINDS)}, "summary": {"type": "string"}, "requirements": {"type": "object"}, "oracle": {"type": "object"}, "expectation": {"type": "object"}, "report": {"type": "object"}, "benign_control": {"type": "string"}, "stable_id_digest": {"type": "string"}}}
def emit(reg) -> dict:
    out = {}
    for sid in sorted(reg):
        m = reg[sid].manifest(); m["schema_version"] = SCHEMA_VERSION; m["benign_control"] = CONTROL[m["suite"]] if m["kind"] == "attack" else "this scenario type IS a benign control (no attack row)"; m["stable_id_digest"] = hashlib.sha256(f"{m['id']}|{m['scenario']}|{m['family']}".encode()).hexdigest()[:16]; out[sid] = m
    return out
def validate(m: dict) -> list:
    """Dependency-free structural validation of the schema above. -> list of problems."""
    sc, p = schema_for(m.get("suite", "")), []
    if m.get("suite") not in SUITES: return ["UNKNOWN_SUITE"]
    for k in sc["required"]:
        if k not in m: p.append(f"MISSING:{k}")
    for k in m:
        if k not in sc["properties"]: p.append(f"UNKNOWN_KEY:{k}")
    if not re.match(sc["properties"]["id"]["pattern"], str(m.get("id", ""))): p.append("BAD_ID")
    if not re.match(sc["properties"]["scenario"]["pattern"], str(m.get("scenario", ""))): p.append("BAD_NAME")
    if m.get("kind") not in KINDS: p.append("BAD_KIND")
    if m.get("fixture_kind") not in FIXTURE_KINDS: p.append("BAD_FIXTURE_KIND")
    if m.get("schema_version") != SCHEMA_VERSION: p.append("BAD_SCHEMA_VERSION")
    r = m.get("requirements") or {}
    if r.get("internet_egress") != "denied" or r.get("real_secrets") != "forbidden": p.append("REQUIREMENTS_WEAKENED")
    if not (m.get("oracle") or {}).get("effect") or not m.get("expectation"): p.append("NO_ORACLE_OR_EXPECTATION")
    return p
def write_all(reg, base=None):
    base = base or os.path.join(ROOT, "benchmarks", "h4"); ms = emit(reg)
    for suite in SUITES:
        os.makedirs(os.path.join(base, suite), exist_ok=True); json.dump(schema_for(suite), open(os.path.join(base, f"{suite}.schema.json"), "w"), indent=1, sort_keys=True)
    for sid, m in ms.items(): json.dump(m, open(os.path.join(base, m["suite"], f"{sid}.json"), "w"), indent=1, sort_keys=True)
    return ms
# ------------------------------------------------------------------ fixture lint (P37-06)
HOST_OK = re.compile(r"^(127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|.*\.(test|invalid|example|localhost)|example\.(com|net|org)|.*\.example\.(com|net|org))$")
URL = re.compile(r"""(?:https?|ftp|ssh|git\+https?|wss?)://([A-Za-z0-9._-]+)""")
_TOKEN_SHAPES = [("aws_access_key", r"AKIA[0-9A-Z]{16}"), ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"), ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}"), ("private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), ("openai_style", r"sk-[A-Za-z0-9]{32,}"), ("google_api", r"AIza[0-9A-Za-z_-]{35}")]
SYNTHETIC_OK = ("AKIA" + "IOSFODNN7EXAMPLE",)       # the AWS documentation example key, published as non-functional
SCAN_EXT = (".py", ".json", ".yml", ".yaml", ".md", ".txt", ".jsonl")
def lint_text(text: str, where: str) -> list:
    out = []; text = re.sub(r'xmlns(:\w+)?=["\'][^"\']*["\']', 'xmlns=""', text)      # XML namespace identifiers are names, not endpoints
    for h in URL.findall(text):
        if not HOST_OK.match(h): out.append({"where": where, "rule": "EXTERNAL_ENDPOINT", "value_sha256": hashlib.sha256(h.encode()).hexdigest()[:12]})
    for name, rx in _TOKEN_SHAPES:
        for m in re.finditer(rx, text):
            v = m.group(0)
            if v in SYNTHETIC_OK or "EXAMPLE" in v.upper() or "TEST_CANARY" in text[max(0, m.start() - 40): m.end() + 40]: continue
            out.append({"where": where, "rule": "REAL_CREDENTIAL_SHAPE:" + name, "value_sha256": hashlib.sha256(v.encode()).hexdigest()[:12]})      # the value itself is never printed
    return out
def lint_tree(paths=None) -> list:
    out = []; paths = paths or [os.path.join(ROOT, "bench", "h4"), os.path.join(ROOT, "benchmarks", "h4"), os.path.join(ROOT, "benchmarks", "hieb")]
    for base in paths:
        for dp, _, fs in os.walk(base):
            if "__pycache__" in dp: continue
            for f in sorted(fs):
                if f.endswith(SCAN_EXT): out += lint_text(open(os.path.join(dp, f), errors="replace").read(), os.path.relpath(os.path.join(dp, f), ROOT))
    return out
