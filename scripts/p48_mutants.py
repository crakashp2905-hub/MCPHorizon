#!/usr/bin/env python3
"""Mutation check for P48: each mutant must make tests.p48.test_consent fail (run on a copy of the tree). Optional argv: only mutants whose description contains one of the words."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); P = lambda x: "horizon/consent/%s.py" % x
CO, SV, MO, OR, RV, HA, SCN = [P(x) for x in ("core", "service", "monitor", "oracle", "review", "harness", "scenarios")]
MUT = [(CO, 'irr = scope == "public"', 'irr = False', "public publish treated as reversible"),
       (CO, 'irr = True; amt = None\n        else', 'irr = False; amt = None\n        else', "send treated as reversible"),
       (CO, '"external": any(e for _, _, e in recv)', '"external": False', "external flag lost"),
       (CO, 'recv = sorted({(self.dest[n]["host"], self.dest[n]["version"], self.dest[n]["external"]) for n in names})', 'recv = sorted({(self.dest[n]["host"], self.dest[n]["version"], self.dest[n]["external"]) for n in names[:1]})', "extra receivers dropped from the manifest"),
       (CO, 'names = [action["destination"]] + list(action.get("mirrors", []))', 'names = [action["destination"]]', "mirrors ignored by the normalizer"),
       (CO, 'names = list(action["recipients"]) + list(action.get("cc", []))', 'names = list(action["recipients"])', "cc ignored by the normalizer"),
       (CO, '"digest": self.content_digest(aid), "version": a["version"]}', '"digest": None, "version": a["version"]}', "content digest missing from the manifest"),
       (CO, 'if bump: a["version"] += 1', 'if False: a["version"] += 1', "edit never bumps the version"),
       (CO, 'if bump: d["version"] += 1', 'if False: d["version"] += 1', "repoint never bumps the version"),
       (CO, '"approvals": max(r["approvals"] for r in hit)', '"approvals": min(r["approvals"] for r in hit)', "requirement takes the weakest rule"),
       (CO, '"level": max(r["level"] for r in hit)', '"level": min(r["level"] for r in hit)', "level takes the weakest rule"),
       (CO, 'if not (m.get("amount") is not None and m["amount"] > v): return False', 'if not (m.get("amount") is not None and m["amount"] >= v): return False', "amount threshold boundary"),
       (CO, 'if bool(m["external"]) != v: return False', 'if False: return False', "external condition ignored"),
       (CO, 'and (("external" not in r) or bool(m["external"]) == r["external"])', 'and (("external" not in r) or True)', "org external condition ignored"),
       (CO, 'and (("scope" not in r) or m["scope"] in r["scope"])', 'and True', "org scope condition ignored"),
       (CO, 'if k in ex and actual[k] != ex[k]: bad.append(k)', 'if k in ex and k != "resource" and actual[k] != ex[k]: bad.append(k)', "envelope ignores the resource"),
       (CO, 'if not set(hosts) <= allowed or len(hosts) > bd.get("max_receivers", len(allowed)): bad.append("receivers")', 'if not set(hosts) <= allowed: bad.append("receivers")', "max receivers ignored"),
       (CO, 'if not set(hosts) <= allowed or len(hosts) > bd.get("max_receivers", len(allowed)): bad.append("receivers")', 'if len(hosts) > bd.get("max_receivers", len(allowed)): bad.append("receivers")', "receiver set ignored"),
       (CO, 'if actual["amount"] is None or actual["amount"] > bd["max_amount"]: bad.append("amount")', 'if actual["amount"] is None or actual["amount"] >= bd["max_amount"]: bad.append("amount")', "amount cap boundary"),
       (CO, 'elif "amount" in ex and actual["amount"] != ex["amount"]: bad.append("amount")', 'elif False: bad.append("amount")', "exact amount ignored"),
       (CO, 'for h in sorted(nh - ph): diff.append("receiver added: " + h)', 'pass', "diff hides added receivers"),
       (CO, 'if unknown: L.append("UNKNOWN (not verified): "', 'if False: L.append("UNKNOWN (not verified): "', "unknown values not stated"),
       (CO, 'L.append("DATA CLASSIFICATION: %s" % m["classification"]);', '', "view omits classification"),
       (CO, '" — IRREVERSIBLE" if m["irreversible"] else', '"" if m["irreversible"] else', "view omits irreversibility"),
       (SV, 'present(self, mode, action, ctx, previous=None, agent_fields=None):\n        if mode in ("effect", "diff"):', 'present(self, mode, action, ctx, previous=None, agent_fields=None):\n        if mode in ("diff",):', "effect view not derived from the manifest"),
       (SV, '"pol": K.policy_digest(self.policy)} if style == "full" else {}', '"pol": "x"} if style == "full" else {}', "policy digest not in the claim"),
       (SV, '"ten": ctx["tenant"], "task": ctx["task"], "ag": ctx["agent"]', '"ten": ctx["tenant"], "task": ctx["task"], "ag": "any"', "agent not in the claim"),
       (SV, 'eff = K.digest(envelope)[:23]', 'eff = "x"', "envelope digest not in the claim"),
       (SV, 'artifact=ctx["task"]', 'artifact="x"', "task not the token artifact"),
       (SV, 'args_digest="*" if (style == "full" and envelope.get("bounds")) or style == "task" else K.digest(action)', 'args_digest="*"', "action digest not bound"),
       (SV, '"owner": ctx["owner"]', '"owner": "nobody"', "ledger records the wrong owner"),
       (MO, 'if pr: return self._done(False, ("ORG_PROHIBITED:"', 'if False: return self._done(False, ("ORG_PROHIBITED:"', "org prohibition not checked"),
       (MO, 'if need is None: return self._done(True, ())', 'if need is None: return self._done(False, ("NO_APPROVAL",))', "no-approval-needed actions denied"),
       (MO, 'if p["kind"] != "APPROVAL": why.append("WRONG_KIND"); continue', 'if False: why.append("WRONG_KIND"); continue', "token kind unchecked"),
       (MO, 'cl.get("ten") != ten', 'False', "tenant unchecked"),
       (MO, '(cl.get("task") != task or p["artifact"] != task)', '(cl.get("task") != task)', "token artifact unchecked"),
       (MO, 'cl.get("ag") != ag', 'False', "agent unchecked"),
       (MO, 'cl.get("pol") != pol', 'False', "policy unchecked"),
       (MO, 'p["args_digest"] != K.digest(a) and not (p["args_digest"] == "*" and env and env.get("bounds"))', 'p["args_digest"] != K.digest(a) and p["args_digest"] != "*"', "wildcard action digest always accepted"),
       (MO, 'K.digest(env)[:23] != cl.get("eff")', 'False', "envelope digest unchecked"),
       (MO, 'apr in (owner, ag)', 'apr == ag', "owner may approve"),
       (MO, 'apr in (owner, ag)', 'apr == owner', "agent may approve"),
       (MO, 'self.policy["authority"].get(apr, 0) < need["level"]', 'self.policy["authority"].get(apr, 0) <= need["level"]', "authority boundary"),
       (MO, 'good[apr] = tok', 'good[tok] = tok', "one approver counted twice"),
       (MO, 'consume=True)', 'consume=False)', "tokens not consumed"),
       (MO, 'for tok in list(good.values())[:n]:\n                try', 'for tok in list(good.values())[:1]:\n                try', "only the first token consumed"),
       (MO, 'if not cfg.bind_tenant: m["tenant"] = None', 'm["tenant"] = None', "tenant stripped from comparison"),
       (OR, 'if e["t"] >= l["t"] + l["ttl"]:', 'if e["t"] > l["t"] + l["ttl"]:', "oracle expiry boundary"),
       (OR, 'if l["policy"] != e["policy"]:', 'if False:', "oracle ignores policy changes"),
       (OR, 'if (l["tenant"], l["task"], l["agent"]) != (e["tenant"], e["task"], e["agent"]):', 'if (l["tenant"], l["task"]) != (e["tenant"], e["task"]):', "oracle ignores agent replay"),
       (OR, 'if l["approver"] in (l["owner"], l["agent"]):', 'if l["approver"] == l["agent"]:', "oracle allows owner self-approval"),
       (OR, 'for l in list(got.values())[:n]: used.add(l["id"])', 'pass', "oracle allows approval reuse"),
       (OR, 'if not set(e["hosts"]) <= set(it["hosts"]): bad.append("hosts")', 'pass', "oracle ignores extra receivers"),
       (OR, 'if it.get("content") and e.get("content") != it["content"]: bad.append("content")', 'pass', "oracle ignores content intent"),
       (OR, 'if e.get("version") != r["version"]: bad.append("version")', 'pass', "oracle ignores approved version"),
       (OR, 'kind = ("DUAL_CONTROL" if got else None) or', 'kind = (None) or', "oracle cannot name dual control"),
       (RV, 'if h not in ok_hosts: obj.append("receiver " + h)', 'pass', "reviewer ignores receivers"),
       (RV, 'fields["resource_digest"] != intent["content"]: obj.append("content")', 'False: obj.append("content")', "reviewer ignores content"),
       (RV, 'elif d < t: om.append(k)', 'elif d < t: ok += 1', "faithfulness counts partial receivers as correct"),
       (HA, 'if not ok: return None, None', 'if False: return None, None', "objecting reviewer still approves"),
       (HA, 'prev = self.prev.get(ctx["task"]) if (s.mode == "diff" or use_prev) else None', 'prev = None', "diff has no previous manifest"),
       (HA, 'if self.sys.gate == "none": ok = True', 'if self.sys.gate == "none": ok = False', "baseline gate inverted"),
       (HA, 'and self.platform.artifacts[a["artifact"]]["classification"] == "SECRET": return False', 'and False: return False', "guardrail SECRET check removed")]


def main():
    surv, ran = [], 0
    for f, a, b, why in [m for m in MUT if not sys.argv[1:] or any(x in m[3] for x in sys.argv[1:])]:
        d = tempfile.mkdtemp(prefix="p48m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target", "results")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p48/test_consent.py", "-k", "not Recorded"], cwd=t, capture_output=True, text=True, timeout=900)
        print(("KILLED  " if r.returncode else "SURVIVED"), why, flush=True)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
