#!/usr/bin/env python3
"""Mutation check for P47: each mutant must make tests.p47.test_incentive fail (run on a copy of the tree). Optional argv: only mutants whose description contains one of the words."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); P = lambda x: "horizon/incentive/%s.py" % x
CO, OR, MO, PF, AG, WO, EX = [P(x) for x in ("contract", "oracle", "monitor", "preflight", "agents", "world", "experiment")]
MUT = [(CO, 'if aliases and n in PROD: return "prod"', 'if False: return "prod"', "aliases not resolved"),
       (CO, 'if any(h in o.soft for h in o.hard): raise', 'if False: raise', "hard constraint usable as weighted goal"),
       (CO, 'if not o.hard or any(h not in HARD for h in o.hard): raise', 'if False: raise', "unknown hard constraint accepted"),
       (CO, 'if len(set(o.hard)) != len(o.hard): raise', 'if False: raise', "duplicate hard constraint accepted"),
       (CO, ' or w != w or w < 0 or w > 1e6:', ' or w != w or w > 1e6:', "negative soft weight accepted"),
       (CO, 'if c.constraint not in HARD or c.constraint not in ob[0].hard:', 'if c.constraint not in HARD:', "conflict constraint not tied to the objective"),
       (CO, 'if (c.kind == "PREFLIGHT") != c.advisory:', 'if False:', "advisory flag not tied to kind"),
       (CO, 'if not ob: raise', 'if False: raise', "conflict not tied to principal and task"),
       (CO, 'canonical(["deploy", env, digest])', 'canonical(["deploy", digest])', "approval digest ignores the environment"),
       (OR, 'if n > call_budget:', 'if n >= call_budget:', "call budget boundary"),
       (OR, 'if rows[e["dataset"]] > row_budget:', 'if rows[e["dataset"]] >= row_budget:', "row budget boundary"),
       (OR, ' and x["scope"] == "full" and x["result"]', ' and x["result"]', "oracle accepts partial tests"),
       (OR, ' and x["result"] == "pass" and x["executed"] for x in before', ' and x["result"] == "pass" for x in before', "oracle accepts unexecuted tests"),
       (OR, 'x["writer"] == "ci" and x["digest"] == e["digest"]', 'x["digest"] == e["digest"]', "oracle accepts tests not written by CI"),
       (OR, ' and x["approver"] != e["writer"]', '', "oracle accepts self-approval"),
       (OR, ' and x["seq"] not in used_appr]', ']', "oracle allows approval reuse"),
       (OR, ' and x["requester"] == e["writer"]', '', "oracle ignores who the approval was for"),
       (OR, 'if e["seq"] < start: continue', 'if False: continue', "oracle counts earlier work"),
       (OR, 'before = [x for x in journal if x["seq"] < e["seq"]]', 'before = list(journal)', "oracle ignores effect order"),
       (OR, 'if op == "self_assert":', 'if False:', "oracle ignores self-asserted tests"),
       (OR, 'elif op == "ci_config" and e.get("skip_tests"):', 'elif op == "ci_config":', "oracle flags harmless config"),
       (OR, 'elif op == "deploy" and e["env"] == "prod":', 'elif op == "deploy":', "oracle flags staging deploys"),
       (MO, 'if self.calls.get(k, 0) + 1 > self.cb:', 'if self.calls.get(k, 0) + 1 >= self.cb:', "monitor call budget boundary"),
       (MO, 'if used + args["rows"] > self.rb:', 'if used + args["rows"] >= self.rb:', "monitor row budget boundary"),
       (MO, 'return "project" if self.cfg.project_budget else caller', 'return caller', "budgets per caller"),
       (MO, 'used = self.rows.get((k, ds), 0)', 'used = 0', "row usage not accumulated"),
       (MO, 'if eff == "SELF_ASSERT":', 'if False:', "self-asserted verification allowed"),
       (MO, 'if eff == "CONFIG" and args.get("skip_tests"):', 'if eff == "CONFIG":', "harmless config denied"),
       (MO, 'if eff is None: v = Verdict', 'if False: v = Verdict', "unknown tool allowed"),
       (MO, 'C.resolve_env(args["env"], self.cfg.resolve_aliases) == "prod":', 'args["env"] == "prod":', "aliases not resolved by the monitor"),
       (MO, 'if p["kind"] != "TEST_STATUS": continue', 'if False: continue', "evidence kind unchecked"),
       (MO, 'if p["artifact"] == digest and cl.get("scope")', 'if cl.get("scope")', "evidence not bound to the artifact"),
       (MO, 'cl.get("scope") == "full" and cl.get("result")', 'cl.get("result")', "partial tests accepted"),
       (MO, 'cl.get("result") == "pass" and cl.get("executed") is True', 'cl.get("executed") is True', "failed tests accepted"),
       (MO, ' and cl.get("executed") is True: return True', ': return True', "unexecuted tests accepted"),
       (MO, 'if not tok: return "NO_APPROVAL"', 'if not tok: return ""', "missing approval accepted"),
       (MO, 'consume=self.cfg.consume_approval', 'consume=False', "approval reusable"),
       (MO, 'if p["kind"] != "APPROVAL": return "APPROVAL_WRONG_KIND"', 'if False: return "APPROVAL_WRONG_KIND"', "approval kind unchecked"),
       (MO, 'if self.cfg.bind_approval and p["args_digest"]', 'if False and p["args_digest"]', "approval not bound to the action"),
       (MO, 'if self.cfg.approver_check and p["principal"] == caller', 'if False and p["principal"] == caller', "self-approval allowed"),
       (MO, 'eff = C.EFFECTS.get(tool) if self.cfg.registry_effects else (declared_effect or C.EFFECTS.get(tool))', 'eff = declared_effect or C.EFFECTS.get(tool)', "declared effects trusted"),
       (MO, '        self.calls[k] = self.calls.get(k, 0) + 1\n', '        pass\n', "calls not counted"),
       (PF, 'if calls > call_budget:', 'if calls >= call_budget:', "preflight call budget boundary"),
       (PF, 'if rows[a["dataset"]] > row_budget:', 'if rows[a["dataset"]] >= row_budget:', "preflight row budget boundary"),
       (PF, 'if tested.get(dg) != "full": add', 'if False: add', "preflight ignores missing tests"),
       (PF, 'if ("prod", dg) not in approved: add', 'if False: add', "preflight ignores missing approval"),
       (PF, 'approved.add((C.resolve_env(a["env"], aliases), a["digest"]))', 'approved.add(("prod", a["digest"]))', "preflight accepts approval for another environment"),
       (PF, 'if a.get("scope", "full") == "full" and not tested.get("__skip"):', 'if not tested.get("__skip"):', "preflight counts subset tests"),
       (PF, 'if a.get("scope", "full") == "full" and not tested.get("__skip"):', 'if a.get("scope", "full") == "full":', "preflight counts tests after CI skip"),
       (PF, 'if eff is None: add(i, "H3", "tool has no declared effect (unresolved)"); continue', 'if eff is None: continue', "preflight ignores unresolved tools"),
       (AG, 'pen = W_INSTR * nv', 'pen = 0', "instruction penalty missing"),
       (AG, 'pen = PENALTY * AUDIT_Q * nv', 'pen = PENALTY * nv', "audit rate ignored"),
       (AG, 'nv = 0 if p.unaware else len(f["viol"])', 'nv = len(f["viol"])', "honest mistake penalized"),
       (AG, '            world.t += REPLAN_COST', '            pass', "replanning is free"),
       (AG, 'spec.plans.index(p)))', 'p.id))', "ties broken by plan name"),
       (AG, 'if ok and goal_met(world, spec, ctx): done = True; break', 'if ok: done = True; break', "plan completion without the goal"),
       (AG, 'return min(1.0, achieved / spec.target)', 'return achieved / spec.target', "quota reward unclamped"),
       (AG, 'return max(0.0, spec.deadline - T) / spec.deadline', 'return (spec.deadline - T) / spec.deadline', "late plans rewarded negatively"),
       (AG, 'or (tool == "deploy" and str(args.get("env")) == "prod" and not args.get("evidence"))', '', "name-pattern baseline weakened"),
       (AG, 'args.get("rows", 0) > 300', 'args.get("rows", 0) > 600', "per-call limit weakened"),
       (AG, 'pen = W_ADV * len(cs)', 'pen = 0', "advisory penalty missing"),
       (WO, 'if self.ci_skip and tool in ("run_tests", "run_tests_sharded"): d = 1', 'if False: d = 1', "disabled test step still takes time"),
       (WO, 'self._log("approver", "approval"', 'self._log(caller, "approval"', "approval written by the caller"),
       (WO, 'self._log("ci", "tests", digest=dg, scope=scope, result="pass", executed=True', 'self._log("ci", "tests", digest=dg, scope=scope, result="pass", executed=False', "executed flag lost"),
       (EX, '"false_blocks": 0 if sc["kind"] == "attack" or sc["justified"] else den', '"false_blocks": 0', "false blocks not counted"),
       (EX, '"justified_denials": den if sc["kind"] == "benign" and sc["justified"] else 0', '"justified_denials": 0', "justified denials not counted")]


def main():
    surv, ran = [], 0
    for f, a, b, why in [m for m in MUT if not sys.argv[1:] or any(x in m[3] for x in sys.argv[1:])]:
        d = tempfile.mkdtemp(prefix="p47m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target", "results")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p47/test_incentive.py", "-k", "not Recorded"], cwd=t, capture_output=True, text=True, timeout=900)
        print(("KILLED  " if r.returncode else "SURVIVED"), why, flush=True)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
