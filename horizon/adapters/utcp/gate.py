"""UTCP direct-call gate (P5-09, P5-18, P5-21). A call is: resolve approved manual tool -> validate target -> decision service -> broker credential -> egress.fetch.
Exactly one place sends traffic (`_send_http`); it is only reachable after an ALLOW for THIS request. Any error before it => nothing is sent."""
from __future__ import annotations
import hashlib, json
from collections import OrderedDict
from . import egress, cli as clix
from .creds import CredentialBroker, CredentialError
from .manual import ManualRegistry, ManualError
from ..mcp.post import label_output

ALLOW = ("ALLOW", "SHADOW_ALLOW")
HTTP_EFFECT = {"GET": "read", "HEAD": "read", "OPTIONS": "read", "POST": "send", "PUT": "modify", "PATCH": "modify", "DELETE": "delete"}


def _sha(o) -> str: return "sha256:" + hashlib.sha256(json.dumps(o, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class UtcpGate:
    def __init__(self, *, decide, registry: ManualRegistry, broker: CredentialBroker, resolver, send, tenant: str, store_artifact=None, sink_zones=None, cli_allowed=frozenset(), cli_cwd="/tmp", budget=egress.Budget(), allowed_hosts=None):
        self.decide, self.reg, self.broker, self.resolver, self.send, self.tenant, self.store = decide, registry, broker, resolver, send, tenant, store_artifact
        self.zones, self.cli_allowed, self.cli_cwd, self.budget, self.allowed_hosts = sink_zones or {}, set(cli_allowed), cli_cwd, budget, allowed_hosts
        self.artifacts: dict[str, dict] = {}; self.done: OrderedDict = OrderedDict(); self.log: list[dict] = []

    def add_artifact(self, a):
        self.artifacts[a["id"]] = a
        if self.store: self.store(a)

    def _out(self, ok, **kw): return {"ok": ok, **kw}

    def call(self, principal: str, call_id: str, manual_id: str, tool: str, args: dict, *, approval_id=None, run_artifacts=(), cred_ref=None, scopes=()) -> dict:
        fp = _sha([manual_id, tool, args, cred_ref]); key = (principal, call_id)
        if key in self.done:
            prior = self.done[key]
            if prior["fp"] != fp: return self._out(False, error="ID_REUSED")
            if prior["state"] == "uncertain": return self._out(False, error="UNCERTAIN_EXECUTION", detail="a previous attempt may have executed")
            return prior["resp"]
        try: resp, state = self._call(principal, call_id, fp, manual_id, tool, args, approval_id, tuple(run_artifacts), cred_ref, tuple(scopes))
        except (ManualError, egress.EgressError, CredentialError, clix.CliError) as e: return self._out(False, error=e.code, detail=str(e)[:200])
        except Exception: return self._out(False, error="GATE_ERROR")                     # fail closed
        if state: self.done[key] = {"fp": fp, "state": state, "resp": resp}
        return resp

    def _call(self, principal, call_id, fp, manual_id, tool, args, approval_id, run_artifacts, cred_ref, scopes):
        m = self.reg.resolve(manual_id, tool); ct = m["template"]
        if not isinstance(args, dict): return self._out(False, error="BAD_ARGS"), None
        inputs = sorted(set(run_artifacts))
        # operator-controlled sink zone (per manual/host), NEVER from the manual's own text
        if ct["call_template_type"] == "http":
            method = (ct.get("http_method") or "GET").upper(); effect = HTTP_EFFECT.get(method)
            if effect is None: return self._out(False, error="METHOD_NOT_SUPPORTED"), None
            native = f"http:{method}"
            url = self._expand(ct["url"], args, ct.get("url_params", {}))
            t = egress.canonical_target(method, url); raw = t["url"]; kind = "url"; self._check_prefix(ct["url"], t["path"])
            if self.allowed_hosts is not None and t["host"] not in self.allowed_hosts: raise egress.EgressError("HOST_NOT_ALLOWED", t["host"])
            ips = egress.resolve_checked(t["host"], self.resolver, t["literal_ip"])          # pre-decision check: forbidden destinations never reach the decision service
        else:
            argv = clix.build_argv(ct.get("commands") or ct.get("command"), args, allowed=self.cli_allowed); effect, kind, raw, t, native = "execute", "command", argv[0], None, "cli:exec"
        body = {"protocol": "utcp", "native_operation": native, "tool_id": f"{manual_id}/{tool}", "effect": effect, "args_digest": _sha(args),
                "target": {"kind": kind, "raw": raw}, "sink_zone": self.zones.get(manual_id), "input_artifacts": inputs,
                "idempotency_key": hashlib.sha256(f"{principal}|{call_id}|{fp}".encode()).hexdigest()[:48], "event_id": f"{principal}-{call_id}"}
        if approval_id: body["approval_id"] = approval_id
        dec = self.decide(body)
        if dec.get("verdict") not in ALLOW: return self._out(False, error="DENIED", verdict=dec.get("verdict"), reason_codes=dec.get("reason_codes", [])), None
        headers = {}
        try:
            if ct["call_template_type"] == "http":
                if cred_ref: headers = self.broker.inject(self.tenant, cred_ref, t, headers, need_scopes=scopes)
                try: r, trail = egress.fetch(method, t["url"], headers, resolver=self.resolver, send=self.send, budget=self.budget, allowed_hosts=self.allowed_hosts)
                except egress.EgressError: raise
                raw_res = {"status": r.status, "body": r.body.decode("utf-8", "replace")}
            else:
                raw_res = clix.run(argv, cwd=self.cli_cwd)
        except (egress.EgressError, CredentialError, clix.CliError): raise
        except Exception:
            return self._out(False, error="UNCERTAIN_EXECUTION"), ("uncertain" if effect not in ("read", "list") else None)
        raw_res = json.loads(CredentialBroker.scrub(json.dumps(raw_res), self.broker.secrets_for(self.tenant)))
        art, safe = label_output(tenant=self.tenant, event_id=f"{principal}-{call_id}", tool_default_conf="INTERNAL", trusted=False, input_artifacts=self.artifacts, input_ids=inputs, result=raw_res)
        self.add_artifact(art)
        resp = self._out(True, result=safe["result"], untrusted=True, artifact_id=safe["artifact_id"], instruction_like=safe["instruction_like"])
        return resp, "done"

    @staticmethod
    def _expand(url: str, args: dict, params: dict) -> str:
        """Only {name} placeholders declared in url_params may be filled, and only into the PATH/QUERY, never scheme/host. Values are percent-encoded."""
        from urllib.parse import quote, urlsplit
        s = urlsplit(url)
        if "{" in (s.scheme + (s.netloc or "")): raise egress.EgressError("HOST_TEMPLATE", "placeholders are not allowed in scheme/host")
        rest = url[len(s.scheme) + 3 + len(s.netloc):]
        for k in params:
            v = args.get(k)
            if not isinstance(v, (str, int)) or isinstance(v, bool): raise egress.EgressError("PARAM", f"missing url parameter {k}")
            if any(c in str(v) for c in "/\\\x00") or str(v) in (".", ".."): raise egress.EgressError("PARAM", f"url parameter {k} may not contain path separators or dot segments")      # canonicalisation decodes %2F and collapses '..'
            rest = rest.replace("{" + k + "}", quote(str(v), safe=""))
        if "{" in rest and "}" in rest: raise egress.EgressError("PARAM", "undeclared placeholder")
        return f"{s.scheme}://{s.netloc}{rest}"

    @staticmethod
    def _check_prefix(template_url: str, final_path: str) -> None:
        """Second layer: whatever the parameters were, the canonical path must still sit under the template's static path prefix."""
        from urllib.parse import urlsplit
        pre = urlsplit(template_url).path.split("{", 1)[0]
        if not final_path.startswith(pre.rsplit("/", 1)[0] + "/" if not pre.endswith("/") else pre): raise egress.EgressError("PATH_ESCAPE", "expanded URL left the template's path prefix")
