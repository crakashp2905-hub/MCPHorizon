#!/usr/bin/env python3
"""Mutation check for P51: each mutant must make tests.p51.test_vision fail (run on a copy of the tree). Optional argv: only mutants whose description contains one of the words."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); P = lambda x: "horizon/vision/%s.py" % x
CO, GU, WO, EX = [P(x) for x in ("core", "guard", "world", "experiment")]
MUT = [(GU, 'if b is None or not b.get("instrumented", False): return', 'if False: return', "unbound action not UNKNOWN"),
       (GU, 'eff = b["effect"] if c.derive_effect else (b["reported"] or {"kind": "NONE"})', 'eff = (b["reported"] or {"kind": "NONE"})', "effect taken from the page report"),
       (GU, 'and act["intent"] != b["element"]["id"]: return', 'and False: return', "element binding off"),
       (GU, 'and b["frame_origin"] not in task["frames"]: return', ': return', "trusted frames not honoured"),
       (GU, 'if c.bind_frame and kind != "NONE" and', 'if c.bind_frame and', "harmless cross-frame action denied"),
       (GU, 'and act["observed"] != b["element"]["digest"]: return', 'and False: return', "staleness unchecked"),
       (GU, 'if c.script_unknown and b.get("script_handled")', 'if False and b.get("script_handled")', "script-handled effect not UNKNOWN"),
       (GU, 'task["allowed"].get(kind, ())', 'task["allowed"].get(kind, (eff.get("dest"),))', "kind absent from policy allowed"),
       (GU, 'eff.get("data") == "canary" and eff.get("dest") not in task["data_dest"]', 'eff.get("data") == "canary" and False', "sensitive data destination unchecked"),
       (GU, 'kind == "SUBMIT" and task.get("reviewed_input") is not None and b["input_digest"] != task["reviewed_input"]', 'kind == "SUBMIT" and False', "reviewed input unchecked"),
       (GU, 'if token is None: return "CONFIRM", "APPROVAL_REQUIRED"', 'if token is None: return "ALLOW", "NO_APPROVAL_NEEDED"', "approval not required"),
       (GU, 'consume=True', 'consume=False', "approval reusable"),
       (GU, 'if p["kind"] != "APPROVAL": return', 'if False: return', "approval kind unchecked"),
       (GU, 'if p["role"] != "approver": return', 'if False: return', "approval role unchecked"),
       (GU, 'if c.bind_approval and p["args_digest"] !=', 'if False and p["args_digest"] !=', "approval not bound to the envelope"),
       (GU, 'if c.approval and kind in task["confirm"]:', 'if c.approval and False:', "protected sinks never confirm"),
       (GU, 'RISK = ("upload", ', 'RISK = (', "screenshot filter ignores upload"),
       (GU, 'if e["kind"] in ("UPLOAD", "DOWNLOAD", "CLIPBOARD"): return', 'if e["kind"] in ("DOWNLOAD", "CLIPBOARD"): return', "blanket rule allows upload"),
       (GU, 'if act["op"] in ("tool_upload", "tool_download")', 'if act["op"] in ("tool_download",)', "tool allowlist allows upload tool"),
       (GU, ' or b.get("frame_origin") in task["blocklist"]', '', "blocklist ignores frame origin"),
       (CO, '[tag, typ, role, eff or {"kind": "NONE"}, frame_origin]', '[tag, typ, role, eff or {"kind": "NONE"}]', "element digest ignores the frame origin"),
       (CO, '"input": input_digest, ', '', "envelope ignores the input"),
       (CO, '"top": top_origin, "tab": tab}', '"tab": tab}', "envelope ignores the top origin"),
       (WO, 'if e.pointer and self.p.frames[e.frame].pointer and _in(e, x, y)', 'if e.pointer and _in(e, x, y)', "frame pointer-events ignored"),
       (WO, 'if e.opacity * self.p.frames[e.frame].opacity > 0 and _in(e, x, y)]\n        return max(c, key=lambda t: (t[0], t[1]))[2] if c else None\n    def find_label', 'if e.opacity > 0 and _in(e, x, y)]\n        return max(c, key=lambda t: (t[0], t[1]))[2] if c else None\n    def find_label', "frame opacity ignored in the screenshot"),
       (WO, 'a <= x < a + w and b <= y < b + h', 'a <= x <= a + w and b <= y <= b + h', "rectangle closed on the far edge"),
       (WO, 'if e is None or e.uninstr or not self.p.page_instrumented: return None', 'if e is None or e.uninstr: return None', "telemetry-off pages still bound"),
       (WO, '"canary" if CANARY in vals else ("plain" if vals else "none")', '"canary" if CANARY in vals else "plain"', "no-input data class"),
       (WO, 'a.get("data", x["data"]) == x["data"] and ', '', "oracle ignores data class"),
       (WO, 'a["dest"] == x["dest"] and ', '', "oracle ignores destination"),
       (WO, 'if eff["kind"] != "NONE": site.receive(eff)', 'site.receive(eff)', "site logs effect-free actions"),
       (WO, 'eff = _real(e, self.p) if not e.script else {"kind": "NONE", "dest": None, "data": "none", "resource": None}', 'eff = _real(e, self.p)', "script effect derivable"),
       (EX, 'if _authorized(eff, sc["authorized"]):', 'if True:', "reviewer approves everything"),
       (EX, 'if d == "ALLOW": perform(br, site, e)', 'if d in ("ALLOW", "UNKNOWN"): perform(br, site, e)', "UNKNOWN executed"),
       (EX, '"unknown": sum(1 for d in decisions if d[0] == "UNKNOWN")', '"unknown": 0', "unknowns not counted"),
       (EX, 'confirms += 1;', 'confirms += 0;', "confirmations not counted"),
       (EX, 'viol = violations(site.log, sc["authorized"])', 'viol = []', "oracle blind"),
       (EX, 'intent, observed = vis.id, br.digest_of(vis)', 'intent, observed = None, None', "agent intent not recorded"),
       ]


def main():
    surv, ran = [], 0
    for f, a, b, why in [m for m in MUT if not sys.argv[1:] or any(x in m[3] for x in sys.argv[1:])]:
        d = tempfile.mkdtemp(prefix="p51m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target", "results")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        try: r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p51/test_vision.py", "-k", "not Recorded"], cwd=t, capture_output=True, text=True, timeout=240)
        except subprocess.TimeoutExpired: r = subprocess.CompletedProcess([], 124, "", "timeout")          # a mutant that makes the suite hang (lock deadlock) is detected
        print(("KILLED  " if r.returncode else "SURVIVED"), why, flush=True)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
