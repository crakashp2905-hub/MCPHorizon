"""K6: the self-hosted developer product's state and trust handling. A HOME directory holds config, public/secret evidence keys, gateway state (journal+anchor+ledger), run bundles and backups.
A run is ALWAYS confined (no silent fallback: if the host cannot confine, the run is refused). Every run produces an evidence bundle signed by a dedicated 'evidence-signer' key — a role distinct from permit issuer, enforcer and installer — that an offline verifier checks with the public key only.
HONEST LIMITS: the evidence key made by `init --dev-keys` is a 0600 file in HOME: dev-grade; production custody is the owner's decision (masterplan section 12). A bundle proves what THIS tool recorded and that it was not altered after signing; it does not prove the host or the tool were uncompromised.
The enforcer key is generated per gateway instance and shipped (public half) inside the signed bundle: the evidence signature binds it, nothing pins it independently. CANDIDATE."""
from __future__ import annotations
import hashlib, io, json, os, shlex, shutil, sqlite3, subprocess, tarfile, time
from horizon.authz.keys import Signer, TrustStore, TrustError
from horizon.effects.filesink import FileSink
from horizon.effects.kernel import verify_receipt
from horizon.effects.mcp_gateway import Gateway
from horizon.contracts.v1 import ContractError
from horizon.runtime import runner as R

EVIDENCE_ROLE = "evidence-signer"; EVIDENCE_KID = "ev1"; VERSION = "0.1.0-candidate"
PROFILES = {
    "strict-repo": {"description": "Edits only through paths you list with --allow; with none listed, no write lands (dry-run). Enforced sandbox, no network, no exec.", "allow_globs": None, "needs_allow": True},
    "standard-repo": {"description": "Common source layout: src/, lib/, tests/, docs/, top-level docs and python files. Enforced sandbox, no network, no exec. Hidden paths (.git, .github, .env, .ssh) are always refused.", "allow_globs": ("src/*", "lib/*", "tests/*", "test/*", "docs/*", "*.md", "*.py", "*.txt"), "needs_allow": False},
    "readonly-audit": {"description": "Runs the agent but lets nothing land; reports what it would have changed.", "allow_globs": (), "needs_allow": False},
}
LIMITS = ["agent is confined by Landlock/seccomp/namespaces on THIS host kernel; not a VM; kernel bugs are out of scope", "exec/syscall attempts by the agent are not logged (no kernel audit): absence of evidence is UNKNOWN",
          "only the harness-side effects are recorded; traffic to destinations outside the empty network namespace is not observed", "path policy cannot tell a malicious edit from a legitimate one inside an allowed path", "deletions are not applied (the gateway is write-only)"]


class ProductError(Exception):
    def __init__(self, code, msg=""): super().__init__(msg or code); self.code = code


def canon(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def sha256(b: bytes) -> str: return "sha256:" + hashlib.sha256(b).hexdigest()
def profile_digest(name: str) -> str: return sha256(canon({"name": name, **{k: (list(v) if isinstance(v, tuple) else v) for k, v in PROFILES[name].items()}}))


def tree_digest(root: str) -> str:
    h = hashlib.sha256()
    for d, ds, fs in os.walk(root):
        ds[:] = sorted(x for x in ds if x != ".git")
        for f in sorted(fs):
            p = os.path.join(d, f)
            if os.path.islink(p): continue
            h.update(os.path.relpath(p, root).encode() + b"\0" + hashlib.sha256(open(p, "rb").read()).digest())
    return "sha256:" + h.hexdigest()


class Home:
    def __init__(self, path: str): self.path = os.path.realpath(path)
    def p(self, *a): return os.path.join(self.path, *a)

    def init(self, *, dev_keys: bool = False) -> dict:
        if os.path.exists(self.p("config.json")): raise ProductError("ALREADY_INITIALISED")
        if not dev_keys: raise ProductError("KEY_REQUIRED", "refusing to invent signing-key custody: pass --dev-keys to create a dev-grade key in this directory, or place your own at keys/evidence.pem (0600) and re-run")
        for d in ("keys", "state", "runs", "backups"): os.makedirs(self.p(d), exist_ok=True)
        s = Signer.generate(EVIDENCE_KID, EVIDENCE_ROLE); s.save(self.p("keys", "evidence.pem")); os.chmod(self.p("keys"), 0o700)
        trust = TrustStore(); trust.add(s.kid, EVIDENCE_ROLE, s.public_raw(), not_before=0, not_after=2 ** 40); json.dump(trust.export_public(), open(self.p("keys", "trust.json"), "w"), indent=1, sort_keys=True)
        cfg = {"version": VERSION, "created": int(time.time()), "key_custody": "DEV-GRADE: secret key is a file in this directory; custody is the owner's decision"}; json.dump(cfg, open(self.p("config.json"), "w"), indent=1)
        return cfg

    def signer(self) -> Signer:
        try: return Signer.load(EVIDENCE_KID, EVIDENCE_ROLE, self.p("keys", "evidence.pem"))
        except (OSError, TrustError) as e: raise ProductError("KEY_UNUSABLE", str(e))
    def trust(self) -> TrustStore: return TrustStore.from_public(json.load(open(self.p("keys", "trust.json"))))
    def require_init(self):
        if not os.path.isfile(self.p("config.json")): raise ProductError("NOT_INITIALISED", "run `hzd init --dev-keys` first")
    def run_ids(self) -> list: return sorted(os.listdir(self.p("runs"))) if os.path.isdir(self.p("runs")) else []
    def load_bundle(self, run_id: str) -> dict:
        if not run_id or "/" in run_id or run_id.startswith("."): raise ProductError("BAD_RUN_ID")
        return json.load(open(self.p("runs", run_id, "bundle.json")))


def sign_bundle(body: dict, signer: Signer) -> dict: return {"body": body, "kid": signer.kid, "alg": "ed25519", "sig": signer.sign(canon(body)).hex()}


def verify_bundle(doc: dict, trust: TrustStore, now: float | None = None) -> dict:
    """Offline verification with the public trust only. Returns {ok, checks}; never raises on malformed input."""
    checks = {}
    try:
        b = doc["body"]; trust.resolve(doc["kid"], EVIDENCE_ROLE, at=now).verify(bytes.fromhex(doc["sig"]), canon(b)); checks["signature"] = True
    except Exception: return {"ok": False, "checks": {"signature": False}}
    try:
        et = TrustStore.from_public(b["enforcer_trust"]); rs = [c["receipt_v1"] for c in b["changes"] if c.get("receipt_v1")]; kids = set()
        for r in rs: verify_receipt(r, et, now=now); kids.add(r["kid"])
        checks["receipts"] = True; checks["receipt_count"] = len(rs); checks["identity_separated"] = doc["kid"] not in kids and all(k in et.k for k in kids)
        checks["landed_have_receipts"] = all(bool(c.get("receipt_v1")) for c in b["changes"] if c["status"] == "ALLOW_COMMITTED")
    except (ContractError, KeyError, TypeError, ValueError, TrustError): checks["receipts"] = False
    checks["kind"] = b.get("kind") == "hzd-evidence-v1"
    return {"ok": all(v is True for k, v in checks.items() if k != "receipt_count"), "checks": checks}


def run_agent(home: Home, repo: str, program: str, *, profile: str = "strict-repo", allow: tuple = (), apply: bool = False, check_cmd: str | None = None, agent_id: str = "local-agent", run_id: str | None = None, extra_env: dict | None = None) -> dict:
    home.require_init(); repo = os.path.realpath(repo)
    if not os.path.isdir(repo): raise ProductError("NO_REPO", repo)
    if profile not in PROFILES: raise ProductError("UNKNOWN_PROFILE", profile)
    prof = PROFILES[profile]
    if allow and prof["allow_globs"] is not None: raise ProductError("PROFILE_FIXED", f"profile {profile} has fixed paths; use strict-repo for --allow")
    globs = tuple(allow) if prof["allow_globs"] is None else prof["allow_globs"]
    if any(g.startswith(".") or "/." in g or g in ("*", "**") for g in globs): raise ProductError("GLOB_TOO_BROAD", "hidden or match-everything globs are refused")
    run_id = run_id or "r%d-%s" % (int(time.time()), hashlib.sha256(os.urandom(8)).hexdigest()[:6])
    if not all(c.isalnum() or c in "-_" for c in run_id): raise ProductError("BAD_RUN_ID")
    signer = home.signer(); runner = R.ConfinedRunner(repo, policy=R.enforced_policy(), timeout_s=60)
    before = tree_digest(repo); rep = runner.run(program, run_id=run_id, extra_env=extra_env)
    if rep.refused: raise ProductError("CANNOT_CONFINE", f"{rep.refused} — refusing to run the agent unconfined")
    os.makedirs(home.p("state"), exist_ok=True)
    gw = Gateway(repo, home.p("state", "journal"), home.p("state", "ledger.db"), allow_subdirs=True, allow_globs=globs, agent_id=agent_id, assurance_claim=("claim:unassured", 0), purpose="hzd-run")
    changes = []
    for i, c in enumerate(rep.changes):
        row = {"path": c["path"], "op": c["op"], "sha256": c["sha256"]}
        if c["op"] == "delete": row.update(status="NOT_APPLIED", code="UNSUPPORTED_EFFECT")
        elif not apply: ok = gw._policy_allows(os.path.join(repo, c["path"])); row.update(status="WOULD_ALLOW" if ok else "WOULD_BLOCK", code=None if ok else "POLICY_DENIED")
        else:
            r = gw.call_write({"path": c["path"], "content": c["data"].decode("utf-8", "replace"), "effect_id": f"{run_id}-{i}"}); sc = r.get("structuredContent", {})
            row.update(status=sc.get("status", "BLOCKED"), code=sc.get("code"), ledger_state=sc.get("ledger_state"), receipt_v1=sc.get("receipt_v1"))
        changes.append(row)
    ok, n, head = gw.sink.verify_chain(); after = tree_digest(repo); check = None
    if check_cmd and apply:
        p = subprocess.run(shlex.split(check_cmd), cwd=repo, capture_output=True, text=True, timeout=300, env={"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}); check = {"cmd": check_cmd, "exit": p.returncode, "tail": (p.stdout + p.stderr)[-400:]}
    body = {"kind": "hzd-evidence-v1", "version": VERSION, "run_id": run_id, "created": int(time.time()), "mode": "apply" if apply else "dry-run", "agent": {"id": agent_id, "program_sha256": sha256(program.encode())},
            "profile": {"name": profile, "digest": profile_digest(profile), "allow_globs": list(globs)}, "runner": {"confined": rep.confined, "policy_digest": rep.policy_digest, "agent_exit": rep.exit, "timed_out": rep.timed_out, "profile": {k: rep.profile.get(k) for k in ("uid", "nonewprivs", "seccomp", "cap_eff")}},
            "repo": {"before": before, "after": after}, "changes": changes, "skipped": rep.skipped, "agent_stdout_sha256": sha256(rep.stdout.encode()), "agent_stdout_head": rep.stdout[:500], "check": check,
            "journal": {"chain_ok": ok, "records": n, "head": head}, "enforcer_trust": gw.enforcer_trust.export_public(), "limits": LIMITS}
    doc = sign_bundle(body, signer); os.makedirs(home.p("runs", run_id), exist_ok=True); json.dump(doc, open(home.p("runs", run_id, "bundle.json"), "w"), indent=1, sort_keys=True)
    return doc


# --------------------------------------------------------------------------------------------- backup / recovery
def backup(home: Home, dest: str | None = None) -> tuple:
    """Deterministic tar.gz of config, PUBLIC keys, state and runs. The secret key is deliberately NOT included: back it up through your own custody."""
    home.require_init(); dest = dest or home.p("backups", "hzd-backup-%d.tar.gz" % int(time.time()))
    if os.path.exists(dest): raise ProductError("EXISTS", dest)
    names = ["config.json", "keys/trust.json"] + [os.path.relpath(os.path.join(d, f), home.path) for sub in ("state", "runs") for d, _, fs in os.walk(home.p(sub)) for f in fs]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for n in sorted(set(names)):
            data = open(home.p(n), "rb").read(); ti = tarfile.TarInfo(n); ti.size = len(data); ti.mtime = 0; ti.mode = 0o600; ti.uid = ti.gid = 0; ti.uname = ti.gname = ""; t.addfile(ti, io.BytesIO(data))
    import gzip
    raw = gzip.compress(buf.getvalue(), mtime=0); open(dest, "wb").write(raw); return dest, sha256(raw)


def recover_check(home: Home) -> dict:
    """Read-only integrity report. UNKNOWN effects are LISTED for an operator to reconcile; nothing is ever auto-resolved or retried."""
    rep = {}
    j = home.p("state", "journal")
    if not os.path.exists(j): rep["journal"] = {"status": "MISSING" if home.run_ids() else "EMPTY"}
    else:
        ok, n, head = FileSink(home.p("state"), j).verify_chain(); rep["journal"] = {"status": "OK" if ok else "FAILED", "records": n, "head": head, "note": "" if ok else "chain/anchor mismatch: tampering, truncation or a lost anchor"}
    db = home.p("state", "ledger.db")
    if not os.path.exists(db): rep["ledger"] = {"status": "MISSING" if home.run_ids() else "EMPTY"}
    else:
        try:
            con = sqlite3.connect("file:%s?mode=ro" % db, uri=True); integ = con.execute("pragma integrity_check").fetchone()[0]; unk = [r[0] for r in con.execute("select effect_id from effects where state='UNKNOWN'")]; con.close()
            rep["ledger"] = {"status": "OK" if integ == "ok" else "FAILED", "unknown_effects": unk, "note": "UNKNOWN effects need operator reconciliation against the sink; they are never auto-resolved" if unk else ""}
        except sqlite3.Error as e: rep["ledger"] = {"status": "FAILED", "note": str(e)}
    tr = home.trust(); bad = []
    for rid in home.run_ids():
        try:
            if not verify_bundle(home.load_bundle(rid), tr)["ok"]: bad.append(rid)
        except Exception: bad.append(rid)
    rep["bundles"] = {"status": "OK" if not bad else "FAILED", "count": len(home.run_ids()), "failed": bad}
    rep["ok"] = all(v["status"] in ("OK", "EMPTY") for v in rep.values() if isinstance(v, dict) and "status" in v); return rep


def restore(backup_path: str, dest: Home, expect_sha256: str) -> dict:
    """Refuses to overwrite, checks the recorded hash BEFORE reading anything, extracts only plain files under known prefixes, then runs recover_check; any failure removes the restored copy."""
    if os.path.exists(dest.path): raise ProductError("EXISTS", dest.path)
    raw = open(backup_path, "rb").read()
    if sha256(raw) != expect_sha256: raise ProductError("HASH_MISMATCH", "backup does not match the hash you recorded")
    import gzip
    try: t = tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw)))
    except Exception as e: raise ProductError("BAD_ARCHIVE", str(e))
    os.makedirs(dest.path)
    try:
        for m in t.getmembers():
            n = m.name
            if not m.isreg() or n.startswith("/") or ".." in n.split("/") or not (n in ("config.json", "keys/trust.json") or n.startswith(("state/", "runs/"))): raise ProductError("BAD_MEMBER", n)
            tgt = dest.p(n); os.makedirs(os.path.dirname(tgt), exist_ok=True); open(tgt, "wb").write(t.extractfile(m).read())
        rep = recover_check(dest)
        if not rep["ok"]: raise ProductError("RESTORED_COPY_FAILED_CHECKS", json.dumps(rep, sort_keys=True))
        return rep
    except BaseException:
        shutil.rmtree(dest.path, ignore_errors=True); raise
