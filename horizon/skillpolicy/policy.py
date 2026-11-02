"""P89: skill supply-chain policy. CANDIDATE, stdlib. Policy is signed and independent of any skill's natural-language text."""
import hashlib, hmac, json, os, re

def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
H = lambda b: hashlib.sha256(b if isinstance(b, bytes) else b.encode()).hexdigest()
CAPS = ("process", "network", "fs_write")
NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$"); VER = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$"); DIG = re.compile(r"^[0-9a-f]{64}$")
REMOTE_INSTALL = re.compile(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba)?sh|pip\s+install\s+(--index-url|-i)\s|npm\s+install\s+\S*(https?|git)[:+]|eval\s*\$\(\s*(curl|wget)", re.I)

class ManifestError(ValueError): pass

def parse_manifest(m):
    """Strict: exact keys, typed, bounded. Raises ManifestError on anything else (no coercion, no unknown keys)."""
    if not isinstance(m, dict): raise ManifestError("not an object")
    need = {"name", "publisher", "version", "digest", "license", "caps", "deps"}
    if set(m) != need: raise ManifestError("keys must be exactly %s" % sorted(need))
    if not (isinstance(m["name"], str) and NAME.match(m["name"])): raise ManifestError("name")
    if not (isinstance(m["publisher"], str) and 0 < len(m["publisher"]) <= 64): raise ManifestError("publisher")
    if not (isinstance(m["version"], str) and VER.match(m["version"])): raise ManifestError("version")
    if not (isinstance(m["digest"], str) and DIG.match(m["digest"])): raise ManifestError("digest")
    if not (isinstance(m["license"], str) and 0 < len(m["license"]) <= 64): raise ManifestError("license")
    c = m["caps"]
    if not isinstance(c, dict) or set(c) != set(CAPS) or not all(isinstance(c[k], list) and len(c[k]) <= 64 and all(isinstance(x, str) and 0 < len(x) <= 256 for x in c[k]) for k in CAPS): raise ManifestError("caps")
    d = m["deps"]
    if not isinstance(d, list) or len(d) > 128 or not all(isinstance(x, str) and 0 < len(x) <= 128 for x in d): raise ManifestError("deps")
    return m

def verify_files(manifest, files):
    """files: {path: bytes}. Digest = sha256 over sorted (path, sha256(content)) pairs."""
    return manifest["digest"] == files_digest(files)
def files_digest(files): return H(canon(sorted((p, H(b)) for p, b in files.items())))

def expansions(old, new):
    """Capability additions between versions, per capability class."""
    return {k: sorted(set(new["caps"][k]) - set(old["caps"][k])) for k in CAPS if set(new["caps"][k]) - set(old["caps"][k])}

class Registry:
    def __init__(self, secret=None): self._k = secret or os.urandom(32); self.allow = {}; self.state = {}; self.history = {}; self.approvals = {}
    def _sig(self, rec): return hmac.new(self._k, canon(rec), hashlib.sha256).hexdigest()
    def approve(self, manifest, approver):
        """Signed allow entry for exactly this digest. Every transitive dependency must itself be allowed."""
        manifest = parse_manifest(manifest)
        for d in manifest["deps"]:
            if self.latest_active(d) is None: raise PermissionError("dependency %s not allowed" % d)
        rec = {"name": manifest["name"], "version": manifest["version"], "digest": manifest["digest"], "caps": manifest["caps"], "approver": approver}
        self.allow[(manifest["name"], manifest["version"])] = dict(rec, sig=self._sig(rec)); self.state[(manifest["name"], manifest["version"])] = "ACTIVE"
        self.history.setdefault(manifest["name"], []).append(manifest["version"])
    def check_install(self, manifest, files):
        """Decision for installing/updating: ALLOW only for a signed, active entry with matching digest and capabilities; otherwise a reason."""
        try: m = parse_manifest(manifest)
        except ManifestError as e: return "DENY", "malformed manifest: %s" % e
        if not verify_files(m, files): return "DENY", "digest mismatch"
        e = self.allow.get((m["name"], m["version"]))
        if e is None:
            prev = self.latest_active(m["name"])
            if prev is not None:
                x = expansions({"caps": prev["caps"]}, m)
                if x: return "NEEDS_REAPPROVAL", "privilege expansion: %s" % x
            return "DENY", "not allowlisted"
        rec = {k: e[k] for k in ("name", "version", "digest", "caps", "approver")}
        if not hmac.compare_digest(e["sig"], self._sig(rec)): return "DENY", "bad policy signature"
        if self.state[(m["name"], m["version"])] != "ACTIVE": return "DENY", "state %s" % self.state[(m["name"], m["version"])]
        if e["digest"] != m["digest"] or e["caps"] != m["caps"]: return "DENY", "differs from approved entry"
        return "ALLOW", ""
    def latest_active(self, name):
        for v in reversed(self.history.get(name, [])):
            if self.state.get((name, v)) == "ACTIVE": return self.allow[(name, v)]
        return None
    def quarantine(self, name, version): self.state[(name, version)] = "QUARANTINED"
    def revoke_publisher_or_version(self, name, version): self.state[(name, version)] = "REVOKED"
    def rollback(self, name):
        """Newest ACTIVE version that is older than any non-active one; running executions keep their pinned version (not touched here)."""
        return self.latest_active(name)

def scan_installers(script_text):
    return bool(REMOTE_INSTALL.search(script_text or ""))

def resolve_instructions(signed_policy, doc_claims):
    """Skill/AGENTS/CLAUDE text is DATA: it can only narrow what the signed policy allows; any widening claim is ignored and reported."""
    out = {"granted": {}, "ignored_widening": {}}
    for k in CAPS:
        allowed, asked = set(signed_policy.get(k, [])), set(doc_claims.get(k, []))
        out["granted"][k] = sorted(allowed & asked) if k in doc_claims else sorted(allowed)
        if asked - allowed: out["ignored_widening"][k] = sorted(asked - allowed)
    return out

def provenance_report(manifest, decision, reason, event):
    return {"event": event, "name": manifest.get("name"), "version": manifest.get("version"), "publisher": manifest.get("publisher"), "digest": manifest.get("digest"), "license": manifest.get("license"), "decision": decision, "reason": reason}
