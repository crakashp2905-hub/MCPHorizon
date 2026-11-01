#!/usr/bin/env python3
"""Mutation check for P44: each mutant must make tests.p44.test_reach fail (run on a copy of the tree)."""
import os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); UN, MO, BR, SR, BL, NW = ["horizon/reach/%s.py" % x for x in ("urlnorm", "model", "broker", "search", "baselines", "network")]
MUT = [(UN, 'if re.search(r"[\\x00-\\x20\\x7f\\\\]", url): raise Unresolvable', 'if False: raise Unresolvable', "backslash/control characters accepted"),
       (UN, 'userinfo = "@" in auth', 'userinfo = False', "userinfo not flagged"),
       (UN, 'host_port = auth.rsplit("@", 1)[-1]', 'host_port = auth.split("@", 1)[0]', "host taken from before the @"),
       (UN, 'if host.endswith("."): host = host[:-1]', 'pass', "trailing dot kept"),
       (UN, 'if ip.ipv4_mapped is not None: host, kind = str(ip.ipv4_mapped), "ipv4"', 'if False: pass', "IPv4-mapped IPv6 not unwrapped"),
       (UN, 'elif re.fullmatch(r"0[0-7]+", p): vals.append(int(p, 8))', 'elif False: pass', "octal parts parsed as decimal"),
       (UN, 'for v in vals[:-1]:\n        if v > 255: raise Unresolvable("numeric host part out of range")', 'for v in vals[:-1]:\n        pass', "oversized numeric part accepted"),
       (UN, 'elif re.fullmatch(r"(0[xX][0-9a-fA-F]*|[0-9]+)", host.lower().rsplit(".", 1)[-1]): raise Unresolvable', 'elif False: raise Unresolvable', "numeric-looking name accepted"),
       (UN, 'if s == ".": continue', 'if s == "x.": continue', "dot segments kept"),
       (UN, 'if not 1 <= port <= 65535: raise Unresolvable("port out of range")', 'pass', "port range unchecked"),
       (UN, 'if scheme not in ("http", "https"): raise Unresolvable("scheme not allowed")', 'pass', "non-http schemes accepted"),
       (MO, 'p["args_digest"] == manifest_digest(m) and ', '', "attestation not bound to manifest digest"),
       (MO, 'p["artifact"] == name and ', '', "attestation not bound to service"),
       (MO, 'and p["claim"].get("key") == m["key"]', '', "attestation not bound to receipt key"),
       (MO, 'except Exception: self.log.append((name, "BAD_MANIFEST_SIGNATURE")); return "REJECTED"', 'except Exception: pass', "unsigned manifest accepted"),
       (MO, 'if r.get("call") != call: return {"state": "MISMATCH"', 'if False: return {"state": "MISMATCH"', "receipt replay across calls accepted"),
       (MO, 'lab = "PUBLIC" if op in CLEAR_OPS else p["label"]', 'lab = "PUBLIC" if op in CLEAR_OPS | KEEP_OPS else p["label"]', "reversible transforms clear the label"),
       (MO, 'if op not in KEEP_OPS | CLEAR_OPS: lab = p["label"]', 'if op not in KEEP_OPS | CLEAR_OPS: lab = "PUBLIC"', "unknown transform clears the label"),
       (BR, 'if c.userinfo: return {"verdict": "UNKNOWN"', 'if False: return {"verdict": "UNKNOWN"', "userinfo URL accepted"),
       (BR, 'except U.Unresolvable as e: return {"verdict": "UNKNOWN"', 'except U.Unresolvable as e: return {"verdict": "ALLOW"', "unresolvable destination allowed"),
       (BR, 'if M.RANK[label] > M.RANK[clear]: return {"verdict": "DENY"', 'if M.RANK[label] > M.RANK[clear] + 5: return {"verdict": "DENY"', "label vs clearance unchecked"),
       (BR, 'return {"verdict": "DENY" if M.RANK[label] > 0 else "ALLOW"', 'return {"verdict": "ALLOW"', "unlisted destination allowed for sensitive data"),
       (BR, 'if egress_of is not None and c.host not in egress_of["egress"]', 'if False and c.host not in egress_of["egress"]', "service egress list ignored"),
       (BR, 'if svc is None or svc != j.get("service"): lab, fetch_ok = "SECRET", frozenset()', 'if False: pass', "unknown/borrowed call id trusted"),
       (BR, 'return self.store.get(artifact)["label"] if self.cfg.bind_labels else (claimed or "PUBLIC")', 'return (claimed or "PUBLIC")', "agent-claimed label trusted"),
       (BR, 'if c.authority != first["canon"].authority:', 'if False:', "authority change after check allowed"),
       (BR, 'if r["verdict"] != "ALLOW" and hops > 0 and self.cfg.revalidate_redirects: return 0, {}, None, trace', 'pass', "redirect hop not revalidated"),
       (BR, 'if M.RANK[label] > 0: verdicts.append("UNKNOWN"); reasons.append("REMOTE_EFFECTS_UNVERIFIED " + name)', 'if False: pass', "unattested service trusted with sensitive data"),
       (BR, 'elif self.registry.status(name) == "REVOKED": verdicts.append("DENY")', 'elif False: verdicts.append("DENY")', "revoked service still callable"),
       (BR, 'rr = self.check_destination(arg, "PUBLIC" if kind == "fetch" else label)', 'rr = self.check_destination(arg, "PUBLIC")', "relay target checked with public label"),
       (BR, 'if rc["state"] != "OK": out["post_verdict"] = "UNKNOWN"', 'if False: pass', "missing receipt treated as success"),
       (BR, 'if bad: out["receipt"] = "REVEALS_UNAUTHORIZED_EFFECT"; out["post_verdict"] = "DENY"; self.registry.revoke(name, "receipt reveals " + bad[0])', 'pass', "receipt-revealed effect ignored"),
       (BR, 'v = "DENY" if "DENY" in verdicts else "UNKNOWN" if "UNKNOWN" in verdicts else "ALLOW"', 'v = "DENY" if "DENY" in verdicts else "ALLOW"', "UNKNOWN collapsed to ALLOW"),
       (BR, 'ip = r["ip"] if self.cfg.pin else', 'ip = self.res.resolve(c.host) if c.kind == "name" else c.host if False else', "pinned address not used"),
       (SR, 'if trust not in accept_trust: unknown = True', 'if False: unknown = True', "unverified edges trusted"),
       (SR, 'if n not in g.modeled: unknown = True', 'if False: unknown = True', "unmodeled node means no path"),
       (SR, 'if g.edges.get(n): exhausted = True; reasons.append("DEPTH_BUDGET")', 'pass', "depth budget exhaustion silent"),
       (SR, 'return "UNKNOWN" if res.unknown else "ALLOW"', 'return "ALLOW"', "unknown search result allowed"),
       (BL, 'if ip not in {self.res.t.get(a) for a in self.allow if a in self.res.t}: return "DENY"', 'pass', "baseline allowlist weakened"),
       (NW, 'RECEIPT', 'RECEIPT', "__noop__")]
MUT = [m for m in MUT if m[3] != "__noop__"]


def main():
    surv, ran = [], 0
    for f, a, b, why in MUT:
        d = tempfile.mkdtemp(prefix="p44m-"); t = os.path.join(d, "t"); shutil.copytree(ROOT, t, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", "target")); s = open(os.path.join(t, f)).read()
        if a not in s: print("NOT APPLICABLE:", why); surv.append(why); shutil.rmtree(d, ignore_errors=True); continue
        open(os.path.join(t, f), "w").write(s.replace(a, b, 1)); ran += 1
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", "pytest", "-x", "-q", "tests/p44/test_reach.py", "-k", "not Recorded"], cwd=t, capture_output=True, text=True, timeout=900)
        print(("KILLED  " if r.returncode else "SURVIVED"), why, flush=True)
        if not r.returncode: surv.append(why)
        shutil.rmtree(d, ignore_errors=True)
    print("%d mutants run, %d survived" % (ran, len(surv))); sys.exit(1 if surv else 0)


main()
