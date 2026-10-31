"""Artifact assurance (P28): sandboxed build, signed manifest, SBOM + pin policy, secret scan, SAST (bandit), SCA (pinned DB snapshot), local exploit oracle, evidence kept SEPARATE (scanner vs oracle),
gate, and a signed release permit bound to artifact digest + destination with deploy-time recheck. Everything is a local research harness: no real registry, no real service."""
from __future__ import annotations
import hashlib, io, json, os, re, resource, shutil, subprocess, sys, tarfile, tempfile, time, zipfile
from horizon.authz.keys import Signer
from horizon.runtime import sandbox as S, schema as SC, provenance as PV
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "..", "bench", "haa", "fixtures", "vuln")
def sha(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def _msg(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------- staging & sandboxed build (P28-01/02)
def stage(files: dict) -> str:
    os.makedirs(S.SCRATCH_BASE, exist_ok=True); d = tempfile.mkdtemp(dir=S.SCRATCH_BASE)
    for rel, data in files.items():
        p = os.path.join(d, rel); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "wb").write(data if isinstance(data, bytes) else data.encode())
    for r, ds, fs in os.walk(d):
        for n in ds + fs: os.chown(os.path.join(r, n), S.UID, S.GID)
    os.chown(d, S.UID, S.GID); return d


def read_tree(d: str) -> dict:
    out = {}
    for r, _, fs in os.walk(d):
        for n in fs: p = os.path.join(r, n); out[os.path.relpath(p, d)] = open(p, "rb").read()
    return out


BUILD_PROG = '''import zipfile, os, py_compile, json
files = sorted(os.path.join(r, f) for r, _, fs in os.walk("src") for f in fs)
for f in files:
    if f.endswith(".py"): py_compile.compile(f, doraise=True, cfile=f + ".chk"); os.remove(f + ".chk")
with zipfile.ZipFile("dist.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for f in files: z.writestr(zipfile.ZipInfo(os.path.relpath(f, "src"), (1980, 1, 1, 0, 0, 0)), open(f, "rb").read())
import socket
try: socket.create_connection(("pypi.org", 443), timeout=1); net = "REACHED"
except OSError as e: net = "denied"
print(json.dumps({"files": len(files), "net": net}))
'''


def build(src: dict, *, run_id="build", source_rev="unknown") -> dict:
    """Builds in the kernel sandbox (no network, no host secrets). Deterministic zip (fixed timestamps). Returns artifact bytes + build facts; refuses (raises) if the sandbox is unavailable."""
    d = stage({("src/" + k): v for k, v in src.items()})
    try:
        r = S.launch(BUILD_PROG, run_id=run_id, scratch=d)
        if r.refused: raise S.Unsupported(r.refused)
        if r.exit != 0 or not r.stdout.strip(): raise RuntimeError("build failed: " + r.stderr[-300:])
        facts = json.loads(r.stdout.strip().splitlines()[-1]); tree = read_tree(d)
        if "dist.zip" not in tree: raise RuntimeError("build produced no artifact")
        return {"artifact": tree["dist.zip"], "artifact_sha256": sha(tree["dist.zip"]), "network": facts["net"], "policy_digest": r.policy_digest, "profile": r.profile, "source_rev": source_rev, "file_sha256": {k: sha(v) for k, v in sorted(src.items()) for v in [v if isinstance(v, bytes) else v.encode()]}}
    finally: shutil.rmtree(d, ignore_errors=True)


def make_manifest(b: dict, signer: Signer, *, builder="hz-sandbox-builder") -> dict:
    body = {"kind": "hz.artifact.v1", "source_rev": b["source_rev"], "builder": {"id": builder, "policy_digest": b["policy_digest"]}, "artifact_sha256": b["artifact_sha256"], "files": b["file_sha256"], "kid": signer.kid}
    return {"body": body, "sig": signer.sign(_msg(body)).hex()}


def verify_manifest(m, pub_raw, artifact: bytes) -> bool:
    try: Ed25519PublicKey.from_public_bytes(pub_raw).verify(bytes.fromhex(m["sig"]), _msg(m["body"]))
    except (InvalidSignature, ValueError, KeyError): return False
    return m["body"]["artifact_sha256"] == sha(artifact)


# ---------------------------------------------------------------- dependency pinning + SBOM (P28-03, HAA-18)
REQ = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+)(?:\s*--hash=sha256:[0-9a-f]{64})*\s*$")
def parse_requirements(text: str, allowed_index="https://pypi.org/simple") -> dict:
    deps, problems = [], []
    for ln in text.splitlines():
        ln = ln.split("#")[0].strip()
        if not ln: continue
        if ln.startswith(("-i", "--index-url", "--extra-index-url", "--find-links", "-f", "-e", "--trusted-host")) or "://" in ln or "@" in ln or ln.startswith(("git+", ".", "/")): problems.append({"line": ln, "code": "UNAUTHORIZED_SOURCE"}); continue
        m = REQ.match(ln)
        if not m: problems.append({"line": ln, "code": "UNPINNED"}); continue
        deps.append({"name": m.group(1).lower().replace("_", "-"), "version": m.group(2), "hashed": "--hash=sha256:" in ln})
    return {"deps": deps, "problems": problems, "ok": not problems}


def sbom(deps: list, artifact_sha: str) -> dict:
    return {"bomFormat": "CycloneDX-lite", "specVersion": "1.5", "metadata": {"component_sha256": artifact_sha}, "components": [{"type": "library", "name": d["name"], "version": d["version"], "purl": f"pkg:pypi/{d['name']}@{d['version']}", "hashed": d["hashed"]} for d in deps]}


# ---------------------------------------------------------------- scanners (kept separate from the oracle)
SECRET_RX = [rx for _, rx in SC.REDACT]
def scan_secrets(blobs: dict) -> list:
    """Scans names->bytes, descending into zip/tar members. Finds secret-shaped strings and the synthetic canary."""
    hits = []
    def one(name, data):
        if data[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for n in z.namelist(): one(f"{name}!{n}", z.read(n))
                return
            except zipfile.BadZipFile: pass
        if data[:2] == b"\x1f\x8b" or data[257:262] == b"ustar":
            try:
                with tarfile.open(fileobj=io.BytesIO(data)) as t:
                    for m in t.getmembers():
                        if m.isfile(): one(f"{name}!{m.name}", t.extractfile(m).read())
                return
            except (tarfile.TarError, OSError): pass
        txt = data.decode("utf-8", "replace")
        if SC.CANARY_PREFIX in txt: hits.append({"where": name, "kind": "CANARY"})
        for kind, rx in SC.REDACT:
            if rx.search(txt): hits.append({"where": name, "kind": kind})
    for n, d in blobs.items(): one(n, d)
    return hits


SEV = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
def sast(path: str) -> dict:
    t0 = time.time()
    try: p = subprocess.run([sys.executable, "-m", "bandit", "-r", "-q", "-f", "json", path], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e: return {"available": False, "why": type(e).__name__}
    try: d = json.loads(p.stdout)
    except ValueError: return {"available": False, "why": "bandit missing or unparsable: " + (p.stderr or p.stdout)[:120]}
    res = [{"id": r["test_id"], "severity": r["issue_severity"], "confidence": r["issue_confidence"], "file": os.path.basename(r["filename"]), "line": r["line_number"]} for r in d["results"]]
    t = d["metrics"]["_totals"]; skipped = sum(v for k, v in t.items() if k.startswith("SEVERITY") is False and k == "skipped_tests")
    return {"available": True, "tool": "bandit", "findings": res, "parse_errors": d["errors"], "loc": t["loc"], "nosec": t.get("nosec", 0), "skipped_tests": skipped, "seconds": round(time.time() - t0, 3), "peak_rss_kb": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            "blocking": [r for r in res if SEV[r["severity"]] == 3 or (SEV[r["severity"]] == 2 and SEV[r["confidence"]] >= 2)], "coverage_warning": "static only; classes without a pattern (authz logic, traversal here) are invisible" + ("; parse errors present" if d["errors"] else "")}


def _vkey(v): return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.+-]", v))
def sca(deps: list, db: dict, pinned_digest: str) -> dict:
    snap = sha(_msg(db["advisories"]))
    if snap != pinned_digest: return {"available": False, "why": "advisory DB snapshot digest mismatch", "got": snap}
    hits = []
    for d in deps:
        for a in db["advisories"]:
            if a["package"] == d["name"] and _vkey(a["introduced"]) <= _vkey(d["version"]) < _vkey(a["fixed"]): hits.append({"package": d["name"], "version": d["version"], "advisory": a["id"], "severity": a["severity"], "fixed": a["fixed"]})
    return {"available": True, "snapshot": snap, "findings": hits, "blocking": [h for h in hits if SEV[h["severity"]] >= 3]}


# ---------------------------------------------------------------- exploit oracle (P28-07/08/09)
def fixture(name, variant) -> dict:
    base = os.path.join(FIXTURES, name); files = {"app.py": open(os.path.join(base, variant, "app.py"), "rb").read()}
    meta = {k: json.load(open(os.path.join(base, f"{k}.json"))) for k in ("exploit", "benign") if os.path.exists(os.path.join(base, f"{k}.json"))}
    return {"files": files, **meta}


SECRET_TEXT = "TEST_CANARY_NOT_SECRET-oracle-asset"
RUN_APP = "import json,sys,importlib\nreq=json.loads(sys.stdin.read())\nimport app\nprint(json.dumps(app.handle(req)))\n"
def _run_app(files: dict, req: dict, run_id: str) -> tuple:
    d = stage({**files, "runner.py": RUN_APP, "secret.txt": SECRET_TEXT})      # the protected asset lives beside the app, NOT inside the shipped artifact
    try:
        r = S.launch(f"import os,sys;sys.path.insert(0,os.getcwd());exec(open('runner.py').read())", run_id=run_id, scratch=d, stdin=json.dumps(req).encode(), policy=S.Policy())
        if r.refused: raise S.Unsupported(r.refused)
        try: out = json.loads(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError): out = {"__error__": r.stderr[-200:]}
        return out, os.listdir(d) + [os.path.join(x, y) for x in os.listdir(d) if os.path.isdir(os.path.join(d, x)) for y in os.listdir(os.path.join(d, x))]
    finally: shutil.rmtree(d, ignore_errors=True)


def oracle(fx: dict, run_id="oracle") -> dict:
    """Runs the intentionally-vulnerable fixture inside the sandbox with the known exploit and decides from its OWN effect evidence (response canary / marker file) — independent of any scanner."""
    ex = fx.get("exploit")
    if not ex: return {"available": False, "why": "no dynamic oracle for this artifact class"}
    out, listing = _run_app(fx["files"], ex["request"], run_id); o = ex["oracle"]
    hit = (o["needle"] in json.dumps(out)) if o["kind"] == "response_contains" else (o["path"] in listing)
    benign = [(_run_app(fx["files"], b["request"], run_id + "-b")[0] == json.loads(json.dumps(b["expect"]).replace("$SECRET", SECRET_TEXT))) for b in fx.get("benign", [])]
    return {"available": True, "exploited": bool(hit), "functional_ok": all(benign) if benign else None, "functional_cases": len(benign), "oracle_kind": o["kind"]}


# ---------------------------------------------------------------- gate + permits + registry (P28-10..13, 16-18)
def evidence(fx: dict, *, deps_text="", db=None, db_digest=None, run_id="ev", scan_dir=None) -> dict:
    """Scanner results and exploit-oracle results are DIFFERENT fields and never merged into one 'score' (P28-10)."""
    d = stage(fx["files"]); 
    try: s = sast(d)
    finally: shutil.rmtree(d, ignore_errors=True)
    reqs = parse_requirements(deps_text); ev = {"scanner": {"sast": s, "sca": sca(reqs["deps"], db, db_digest) if db is not None else {"available": False, "why": "no advisory DB"}, "secrets": scan_secrets(fx["files"]), "deps": reqs}, "oracle": oracle(fx, run_id)}
    ev["digest"] = sha(_msg(ev)); return ev


def gate(ev: dict) -> dict:
    """ALLOW only when every required control produced evidence and none blocks. Missing evidence is UNKNOWN, never PASS."""
    r, sc, orc = [], ev["scanner"], ev["oracle"]
    if not sc["sast"].get("available"): r.append("SAST_UNAVAILABLE")
    if not sc["sca"].get("available"): r.append("SCA_UNAVAILABLE")
    if r: return {"decision": "UNKNOWN", "reasons": r}
    b = []
    if orc.get("available") and orc["exploited"]: b.append("ORACLE_EXPLOITED")
    if orc.get("available") and orc["functional_ok"] is False: b.append("FUNCTIONAL_REGRESSION")
    if sc["sast"]["blocking"]: b.append("SAST_BLOCKING:" + ",".join(sorted({x["id"] for x in sc["sast"]["blocking"]})))
    if sc["sca"]["blocking"]: b.append("SCA_BLOCKING")
    if sc["secrets"]: b.append("SECRET_IN_ARTIFACT")
    if not sc["deps"]["ok"]: b.append("DEPENDENCY_POLICY:" + ",".join(sorted({p["code"] for p in sc["deps"]["problems"]})))
    resid = [] if orc.get("available") else ["NO_DYNAMIC_ORACLE"]
    return {"decision": "BLOCK" if b else "ALLOW", "reasons": b, "residual": resid}


def issue_permit(signer: Signer, *, artifact_sha256, destination, evidence_digest, ttl_s=300, now=None, exception=None) -> dict:
    body = {"kind": "hz.release.v1", "artifact_sha256": artifact_sha256, "destination": destination, "evidence_digest": evidence_digest, "exp": int((now or time.time()) + ttl_s), "exception": exception, "kid": signer.kid}
    return {"body": body, "sig": signer.sign(_msg(body)).hex()}


def exception_permit(signer: Signer, approval: dict, approver_pub: bytes, *, artifact_sha256, destination, evidence_digest, policy_digest, now=None) -> dict:
    """Release exception (P28-18): requires an authenticated ADMIN approval scoped to this artifact+destination. An agent/user role cannot mint one."""
    PV.check_approval(approval, approver_pub, policy_digest=policy_digest, want_scope={"artifact_sha256": artifact_sha256, "destination": destination}, now=now)
    if approval["body"]["role"] != "admin": raise PV.ApprovalError("ADMIN_REQUIRED")
    return issue_permit(signer, artifact_sha256=artifact_sha256, destination=destination, evidence_digest=evidence_digest, now=now, exception={"approver": approval["body"]["approver"], "role": "admin"})


class MockRegistry:
    """The ONLY write path to the release store. publish() itself enforces the permit — there is no unchecked method to call (P28-11/13)."""
    def __init__(self, destination, pub_raw, clock=time.time): self.dest, self.pub, self.clock, self.releases, self.rejections = destination, pub_raw, clock, [], []
    def publish(self, artifact: bytes, permit: dict | None) -> dict:
        def no(code): self.rejections.append(code); return {"ok": False, "code": code}
        if not permit: return no("NO_PERMIT")
        try: Ed25519PublicKey.from_public_bytes(self.pub).verify(bytes.fromhex(permit["sig"]), _msg(permit["body"]))
        except (InvalidSignature, ValueError, KeyError): return no("BAD_PERMIT_SIGNATURE")
        b = permit["body"]
        if b["destination"] != self.dest: return no("WRONG_DESTINATION")
        if self.clock() > b["exp"]: return no("PERMIT_EXPIRED")
        if sha(artifact) != b["artifact_sha256"]: return no("ARTIFACT_DIGEST_MISMATCH")               # re-checked at deploy time, not trusted from build time
        self.releases.append({"sha256": b["artifact_sha256"], "evidence": b["evidence_digest"], "exception": b["exception"]}); return {"ok": True}
