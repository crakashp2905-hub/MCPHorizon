"""hzd: the self-hosted developer CLI (K6). Offline: stdlib + `cryptography`; the only network use is the optional local-model endpoint on loopback. Exit codes: 0 ok, 1 refused/failed verification, 2 usage."""
from __future__ import annotations
import argparse, json, os, platform, sys
from horizon.product import home as H


def _out(o): print(json.dumps(o, indent=1, sort_keys=True, default=str))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hzd"); ap.add_argument("--home", default=os.environ.get("HZD_HOME", os.path.expanduser("~/.hzd"))); sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init"); i.add_argument("--dev-keys", action="store_true")
    sub.add_parser("version"); sub.add_parser("doctor"); sub.add_parser("profiles")
    r = sub.add_parser("run"); r.add_argument("--repo", required=True); r.add_argument("--program", required=True, help="python file the agent runs (confined)"); r.add_argument("--profile", default="strict-repo"); r.add_argument("--allow", action="append", default=[]); r.add_argument("--apply", action="store_true"); r.add_argument("--check-cmd")
    m = sub.add_parser("model-run"); m.add_argument("--repo", required=True); m.add_argument("--endpoint", required=True); m.add_argument("--model", required=True); m.add_argument("--task", required=True); m.add_argument("--profile", default="strict-repo"); m.add_argument("--allow", action="append", default=[]); m.add_argument("--apply", action="store_true"); m.add_argument("--check-cmd")
    v = sub.add_parser("verify"); v.add_argument("bundle"); v.add_argument("--trust", help="trust.json (default: HOME/keys/trust.json)")
    sub.add_parser("runs"); d = sub.add_parser("dashboard"); d.add_argument("--port", type=int, default=8765); d.add_argument("--host", default="127.0.0.1")
    b = sub.add_parser("backup"); b.add_argument("--dest"); rs = sub.add_parser("restore"); rs.add_argument("backup"); rs.add_argument("--sha256", required=True); sub.add_parser("recover")
    a = ap.parse_args(argv); home = H.Home(a.home)
    try:
        if a.cmd == "version": _out({"hzd": H.VERSION}); return 0
        if a.cmd == "profiles": _out({k: {"description": p["description"], "allow_globs": p["allow_globs"], "digest": H.profile_digest(k)} for k, p in H.PROFILES.items()}); return 0
        if a.cmd == "doctor":
            from horizon.runtime import sandbox as S
            can = os.geteuid() == 0 and platform.machine() == "x86_64" and S.landlock_abi() >= 4
            c = {"python>=3.11": sys.version_info >= (3, 11), "can_confine_agents_here": can, "initialised": os.path.isfile(home.p("config.json"))}
            _out({"checks": c, "note": "agents are refused, never run unconfined, when can_confine_agents_here is false (needs root, x86_64, Landlock ABI>=4)"}); return 0 if c["python>=3.11"] else 1
        if a.cmd == "init": _out(home.init(dev_keys=a.dev_keys)); return 0
        if a.cmd in ("run", "model-run"):
            if a.cmd == "run": program = open(a.program).read()
            else:
                from horizon.product import model as M
                program, _ = M.propose_program(a.endpoint, a.model, a.task, a.repo)
            doc = H.run_agent(home, a.repo, program, profile=a.profile, allow=tuple(a.allow), apply=a.apply, check_cmd=a.check_cmd, agent_id="model-agent" if a.cmd == "model-run" else "local-agent")
            bd = doc["body"]; _out({"run_id": bd["run_id"], "mode": bd["mode"], "changes": [{k: c.get(k) for k in ("path", "op", "status", "code")} for c in bd["changes"]], "check": bd["check"], "bundle": home.p("runs", bd["run_id"], "bundle.json")}); return 0
        if a.cmd == "verify":
            tr = H.TrustStore.from_public(json.load(open(a.trust or home.p("keys", "trust.json")))); res = H.verify_bundle(json.load(open(a.bundle)), tr); _out(res); return 0 if res["ok"] else 1
        if a.cmd == "runs": _out(home.run_ids()); return 0
        if a.cmd == "dashboard":
            from horizon.product import dashboard as D
            srv = D.serve(home, a.host, a.port); print(f"hzd dashboard on http://{a.host}:{srv.server_address[1]}/ (read-only, loopback, no auth)", flush=True); srv.serve_forever(); return 0
        if a.cmd == "backup": p, h = H.backup(home, a.dest); _out({"backup": p, "sha256": h, "record_this_hash_somewhere_the_tool_cannot_rewrite": True, "secret_key_included": False}); return 0
        if a.cmd == "restore": _out(H.restore(a.backup, home, a.sha256)); return 0
        if a.cmd == "recover": rep = H.recover_check(home); _out(rep); return 0 if rep["ok"] else 1
    except (H.ProductError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"hzd: {getattr(e, 'code', type(e).__name__)}: {e}", file=sys.stderr); return 1
    except Exception as e:
        from horizon.product import model as M
        if isinstance(e, M.ModelError): print(f"hzd: {e}", file=sys.stderr); return 1
        raise
    return 2


if __name__ == "__main__": sys.exit(main())
