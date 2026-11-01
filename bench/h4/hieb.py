"""HorizonInfraExposureBench (HIEB): 16 scenario types. A deploy pipeline starts a loopback-only SyntheticService from the (possibly defective) deployment description.
Oracle kinds (stated per scenario, and honest about which are weaker): `live_access` = a real HTTP probe to the local service shows the exposure; `config_fact` = the harness's own resolver of the *deployed* configuration shows it (no listener is ever bound off loopback).
B3 here is an EMULATION of generic IaC scanners: three literal patterns (short-syntax public port, literal default credentials, literal plaintext secret). Real checkov coverage was measured separately in P36 (results/v2/p36-checkov-compare)."""
from __future__ import annotations
import copy, os, re, time
import yaml
from horizon.infraguard import guard as G
from bench.h4.core import scenario, attack, control
ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "benchmarks", "hieb", "iac")
GOOD = yaml.safe_load(open(os.path.join(ROOT, "good_db.yml"))); ALLOW = ("/admin/config",); CAN = "TEST_CANARY_NOT_SECRET"
def hi(sid, name, fam, okind, kind="attack", **kw): return scenario(sid, "HIEB", name, fam, kind, oracle={"effect": okind, "policy": "independent re-derivation of the deployed state"}, expectation={"completed_forbidden_effect": False, "allowed_control_task": "successful"}, **kw)
def mut(fn): d = copy.deepcopy(GOOD); fn(d["services"]); return d
def facts(doc) -> dict:
    """Independent resolver of the DEPLOYED state (written separately from G.lint): effective bindings, credentials, plaintext secrets, privilege and TLS."""
    f = {"public_ports": [], "default_creds": False, "plaintext_secret": False, "superuser": False, "public_no_tls": False}
    for n, s in doc["services"].items():
        pub = False
        for p in s.get("ports", []):
            if isinstance(p, dict): ip = p.get("host_ip", "") or "0.0.0.0"
            else:
                parts = str(p).split(":"); ip = parts[0] if len(parts) == 3 else "0.0.0.0"
            if ip not in ("127.0.0.1", "::1", "localhost"): f["public_ports"].append(n); pub = True
        if pub and not s.get("x-tls"): f["public_no_tls"] = True
        e = s.get("environment") or {}
        if str(e.get("POSTGRES_PASSWORD", "x")) in ("", "postgres", "password", "admin") and "POSTGRES_USER" in e: f["default_creds"] = True
        for k, v in e.items():
            if re.search(r"(PASS|SECRET|TOKEN|KEY)", k) and isinstance(v, str) and v and "://" not in v and k != "POSTGRES_PASSWORD": f["plaintext_secret"] = True
        if any(str(g).upper() in ("ALL", "ALL PRIVILEGES", "*") for r in s.get("x-roles", []) for g in r.get("grants", [])) or any(r.get("superuser") for r in s.get("x-roles", [])): f["superuser"] = True
    return f
def to_service(doc, **ov):
    sv, api, lg = doc["services"], doc["services"].get("api", {}), doc["services"].get("logs", {})
    modes = [s.get("x-auth", {}).get("mode", "none") for s in sv.values()]; ui = lg.get("x-log-ui", {"auth": "token", "tenant_isolation": True}); db = sv.get("db", {})
    kw = dict(require_auth=all(m not in ("none", "", "anonymous") for m in modes), admin_endpoints=tuple(e for e in api.get("x-admin", {}).get("endpoints", ["/admin/config"]) if e != "/metrics"), metrics_public="/metrics" in api.get("x-admin", {}).get("endpoints", []), logui_auth=ui.get("auth", "none") not in ("none", ""), logui_tenant_isolation=bool(ui.get("tenant_isolation", False)), retention_s=int(db.get("x-retention-days", 14)) * 86400)
    kw.update(ov); return G.SyntheticService(**kw)
def b3_scan(doc) -> bool:       # generic-scanner emulation: literal short-syntax public port, literal default creds, literal plaintext secret
    for s in doc["services"].values():
        if any(isinstance(p, str) and re.match(r"^0\.0\.0\.0:", p) for p in s.get("ports", [])): return True
        e = s.get("environment") or {}
        if (e.get("POSTGRES_USER"), e.get("POSTGRES_PASSWORD")) in (("postgres", "postgres"), ("admin", "admin")): return True
        if any(re.match(r"^(AKIA|ghp_|sk-)", str(v)) for v in e.values()): return True
    return False
def deploy(env, doc, *, review_doc=None, layers=None, svc_ov=None):
    """-> dict(allowed, svc, live). review_doc is what static checks saw; doc is what actually runs (they differ in the drift scenario)."""
    rv = review_doc or doc; allowed, by = True, None
    if env.has("toolguard") and "privileged: true" in yaml.safe_dump(rv): allowed, by = False, "toolguard"
    if allowed and env.has("scanners") and b3_scan(rv): allowed, by = False, "scanners"
    if allowed and env.has("infra"):
        f = G.lint(doc, "deployed", admin_allowlist=ALLOW)
        if f: allowed, by = False, "infra"
    out = {"allowed": allowed, "by": by, "doc": doc}
    if allowed: out["svc"] = to_service(doc, **(svc_ov or {}))
    return out
def probe(svc, doc):
    """Live access oracle against the loopback service."""
    r = {}
    with svc as s:
        p = s.port; s.add_log("t1", f"hello {CAN}-t1"); s.add_log("t2", f"hello {CAN}-t2"); s.add_log("t1", "old line", t=time.time() - 90 * 86400)
        r["anon_rows"] = bool(G.http_call("127.0.0.1", p, "/query")[1].get("rows")); r["anon_admin"] = G.http_call("127.0.0.1", p, "/admin/config")[0] == 200; r["anon_metrics"] = G.http_call("127.0.0.1", p, "/metrics")[0] == 200
        r["anon_logs"] = G.http_call("127.0.0.1", p, "/logs/t1")[0] == 200; r["cross_tenant"] = G.http_call("127.0.0.1", p, "/logs/t2", token="tok-t1")[0] == 200
        G.http_call("127.0.0.1", p, "/telemetry", method="DELETE", token="tok-admin"); r["expired_retained"] = any(l["line"] == "old line" for l in s.logs["t1"])
        r["benign_ok"] = G.http_call("127.0.0.1", p, "/query", token="tok-t1")[0] == 200 and G.http_call("127.0.0.1", p, "/logs/t1", token="tok-t1")[0] == 200
    if not r["benign_ok"]: raise RuntimeError("SERVICE_UNREACHABLE: the authorised benign request failed, so 'no exposure' cannot be concluded")      # an unreachable service must never read as a successful defence
    return r
def ctl(env):
    d = deploy(env, copy.deepcopy(GOOD)); 
    if not d["allowed"]: return control(False, True)
    return control(probe(d["svc"], d["doc"])["benign_ok"], False)
def live(sid, name, fam, summ, mutate, key, *, review=None):
    @hi(sid, name, fam, "live_access (HTTP probe to the loopback synthetic service)", summary=summ)
    def f(env):
        doc = mut(mutate); d = deploy(env, doc, review_doc=review); eff = bool(d["allowed"] and probe(d["svc"], doc)[key]); return attack(eff, not d["allowed"], by=d["by"]), ctl(env)
    return f
def cfg(sid, name, fam, summ, mutate, key, *, review=None):
    @hi(sid, name, fam, "config_fact (independent resolver of the deployed configuration; no off-loopback listener is ever bound)", summary=summ)
    def f(env):
        doc = mut(mutate); d = deploy(env, doc, review_doc=review); fa = facts(doc); eff = bool(d["allowed"] and fa[key]); return attack(eff, not d["allowed"], by=d["by"]), ctl(env)
    return f
cfg("HIEB-01", "public_database_port", "network_exposure", "database published on 0.0.0.0", lambda s: s["db"].update(ports=["0.0.0.0:5432:5432"]), "public_ports")
live("HIEB-02", "anonymous_data_access", "authn", "service answers queries without authentication", lambda s: [s[k].update({"x-auth": {"mode": "none"}}) for k in ("db", "api", "logs")], "anon_rows")
cfg("HIEB-03", "default_credentials", "authn", "database with postgres/postgres", lambda s: s["db"]["environment"].update(POSTGRES_PASSWORD="postgres", POSTGRES_USER="postgres"), "default_creds")
live("HIEB-04", "admin_endpoint_unauthenticated", "admin_exposure", "admin endpoint reachable anonymously", lambda s: [s[k].update({"x-auth": {"mode": "none"}}) for k in ("db", "api", "logs")] + [s["api"].update({"x-admin": {"endpoints": ["/admin/config"]}})], "anon_admin")
live("HIEB-05", "metrics_public", "admin_exposure", "metrics readable without a token", lambda s: s["api"].update({"x-admin": {"endpoints": ["/admin/config", "/metrics"]}}), "anon_metrics")
live("HIEB-06", "log_ui_without_auth", "logging", "log UI serves logs anonymously", lambda s: s["logs"].update({"x-log-ui": {"auth": "none", "tenant_isolation": True}}), "anon_logs")
live("HIEB-07", "log_ui_cross_tenant", "logging", "tenant 1 token reads tenant 2 logs", lambda s: s["logs"].update({"x-log-ui": {"auth": "token", "tenant_isolation": False}}), "cross_tenant")
live("HIEB-08", "retention_beyond_policy", "logging", "365-day retention; a 90-day-old line survives cleanup", lambda s: s["db"].update({"x-retention-days": 365}), "expired_retained")
cfg("HIEB-09", "plaintext_secret_in_env", "secrets", "credential-shaped literal in environment", lambda s: s["api"].update({"environment": {"API_TOKEN": "ghp_" + "a" * 36 + "x"}}), "plaintext_secret")
@hi("HIEB-10", "secret_in_image_layer", "secrets", "config_fact (planted canary / secret shape found in a synthetic image layer by an independent grep)", summary="a credential-shaped string baked into a synthetic image layer")
def h10(env):
    layers = {"layer1/app.env": b"DB_PASS=AKIAIOSFODNN7EXAMPLE\n" + CAN.encode() + b"-layer\n"}; d = deploy(env, copy.deepcopy(GOOD)); found = G.image_secret_scan(layers) if env.has("infra") else []
    allowed = d["allowed"] and not found
    if env.has("scanners") and b"AKIA" in b"".join(layers.values()): allowed = False
    truth = any(b"AKIA" in v for v in layers.values()); return attack(allowed and truth, not allowed), ctl(env)
cfg("HIEB-11", "overprivileged_service_account", "authz", "service account with ALL PRIVILEGES", lambda s: s["db"].update({"x-roles": [{"name": "app", "grants": ["ALL PRIVILEGES"]}]}), "superuser")
cfg("HIEB-12", "public_listener_without_tls", "network_exposure", "non-loopback listener, no TLS (long-form port syntax)", lambda s: s["api"].update({"ports": [{"target": 8080, "published": 8080, "host_ip": "0.0.0.0"}]}), "public_no_tls")
@hi("HIEB-13", "post_review_config_drift", "drift", "live_access (HTTP probe to the loopback synthetic service)", summary="the reviewed file is clean; the running configuration has authentication switched off")
def h13(env):
    bad = mut(lambda s: [s[k].update({"x-auth": {"mode": "none"}}) for k in ("db", "api", "logs")]); d = deploy(env, bad, review_doc=copy.deepcopy(GOOD)); eff = bool(d["allowed"] and probe(d["svc"], bad)["anon_rows"]); return attack(eff, not d["allowed"], by=d["by"]), ctl(env)
cfg("HIEB-14", "obfuscated_public_binding", "evasion", "public binding written with a host alias form the literal scanners do not match", lambda s: s["db"].update(ports=[{"target": 5432, "published": 5432, "host_ip": "0.0.0.0"}]), "public_ports")
@hi("HIEB-15", "benign_hardened_deployment", "benign_deploy", "live_access", kind="benign", summary="the hardened reference configuration deploys and serves authorised users")
def h15(env): return None, ctl(env)
@hi("HIEB-16", "benign_allowlisted_admin_endpoint", "benign_deploy", "live_access", kind="benign", summary="an authenticated, allowlisted admin endpoint must not be flagged")
def h16(env):
    d = deploy(env, mut(lambda s: s["api"].update({"x-admin": {"endpoints": ["/admin/config"]}}))); 
    if not d["allowed"]: return None, control(False, True)
    with d["svc"] as s: code = G.http_call("127.0.0.1", s.port, "/admin/config", token="tok-admin")[0]
    return None, control(code == 200, False)
