"""Mutation check for horizon/forge/pareto.py, horizon/coverage/schema.py, security_hardening/roadmap.py (timeout counts as killed)."""
import subprocess, sys, os
M = [
 ("horizon/forge/pareto.py", [
  ('if not any(o != k and o[0] <= k[0] and o[1] <= k[1] for o in pts): out.append', 'if True: out.append'),
  ('if k not in best or repr(p) < repr(best[k]): best[k] = p', 'if k not in best: best[k] = p'),
  ('FULL_LOSS = 2', 'FULL_LOSS = 1'),
  ('0 <= max_utility_loss < FULL_LOSS', '0 <= max_utility_loss <= FULL_LOSS'),
  ('and 0 <=', 'and -1 <='),
  ('if utility_loss(task, p) <= max_utility_loss]', 'if utility_loss(task, p) <= FULL_LOSS]'),
  ('"deny_all": {"is_solution": False,', '"deny_all": {"is_solution": True,'),
  ('best = min(ok, key=lambda p: (p.cost(), utility_loss(task, p), repr(p)))', 'best = max(ok, key=lambda p: (p.cost(), utility_loss(task, p), repr(p)))'),
  ('if len(set(pts)) != len(pts): return False', 'pass'),
  ('if not checker.check(task, p) or (p.cost(), utility_loss(task, p)) != k: return False', 'if (p.cost(), utility_loss(task, p)) != k: return False'),
  ('if any(a[0] <= k[0] and a[1] <= k[1] and a != k for a in adm): return False', 'pass'),
  ('return all(any(k[0] <= a[0] and k[1] <= a[1] for k in pts) for a in adm)', 'return True'),
  ('(p.cost(), utility_loss(task, p)) != k: return False\n', '(p.cost(), utility_loss(task, p)) != k and False: return False\n'),
 ]),
 ("horizon/coverage/schema.py", [
  ('if not (isinstance(v, str) and _ID.fullmatch(v)): raise SchemaError', 'if False: raise SchemaError'),
  ('if v not in allowed: raise', 'if False: raise'),
  ('if set(d) - names: raise', 'if False: raise'),
  ('if names - set(d): raise', 'if False: raise'),
  ('if self.src == self.dst: raise', 'if False: raise'),
  ('if self.synthetic_only is not True: raise', 'if False: raise'),
  ('or isinstance(self.max_external_effects, bool)', 'or False') if False else ('and not isinstance(self.max_external_effects, bool) and self.max_external_effects == 0', 'and self.max_external_effects == 0'),
  ('self.max_external_effects == 0)', 'self.max_external_effects >= 0)'),
  ('return z is not None and z.authority in ("receiver", "operator")', 'return z is not None'),
  ('z.authority in ("receiver", "operator")', 'z.authority in ("receiver", "operator", "agent")'),
  ('sees = edge.dst in witness.channels and edge.instrumentation == "instrumented"', 'sees = edge.dst in witness.channels'),
  ('sees = edge.dst in witness.channels and', 'sees = True and'),
  ('if not sees: raise SchemaError("witness reported', 'if False: raise SchemaError("witness reported'),
  ('"POSITIVE_INDEPENDENT" if witness.independent_of(zones) else "POSITIVE_SELF_REPORTED"', '"POSITIVE_INDEPENDENT"'),
  ('    return "UNKNOWN"', '    return "NOT_PRESENT" if o.outcome == "not_seen" else "UNKNOWN"'),
  ('if o.edge_dst != edge.dst or o.witness != witness.name: raise', 'if False: raise'),
  ('if o.edge_dst != edge.dst or', 'if'),
  ('if not (isinstance(self.channels, frozenset) and self.channels and', 'if not (isinstance(self.channels, frozenset) and'),
  ('def digest(self) -> str:\n        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True,', 'def digest(self) -> str:\n        return hashlib.sha256(json.dumps({}, sort_keys=True,'),
 ]),
 ("security_hardening/roadmap.py", [
  ('STATUSES = ("OPEN", "CANDIDATE", "BLOCKED")', 'STATUSES = ("OPEN", "CANDIDATE", "BLOCKED", "DONE")'),
  ('if status.get("doc_sha256") != doc_sha: p.append', 'if False: p.append'),
  ('for t in sorted(set(doc_tasks) - set(tasks)): p.append', 'for t in []: p.append'),
  ('for t in sorted(set(tasks) - set(doc_tasks)): p.append', 'for t in []: p.append'),
  ('if t.endswith("-GATE") and s == "CANDIDATE": p.append', 'if False: p.append'),
  ('if not (isinstance(ev, dict) and ev): p.append', 'if False: p.append'),
  ('not full.startswith(os.path.realpath(root) + os.sep) or', 'False or'),
  ('or not os.path.isfile(full): p.append', 'or False: p.append'),
  ('elif sha(full) != d: p.append', 'elif False: p.append'),
  ('if not (isinstance(r.get("note"), str) and r["note"].strip()): p.append', 'if False: p.append'),
  ('if s == "BLOCKED" and not (isinstance(r.get("blocked_by"), str) and r["blocked_by"].strip()): p.append', 'if False: p.append'),
  ('if s == "OPEN" and (r.get("evidence") or r.get("blocked_by")): p.append', 'if False: p.append'),
  ('set(r) - {"status", "evidence", "blocked_by", "note"}', 'set(r) - {"status", "evidence", "blocked_by", "note", "verified_by"}'),
  ('if not isinstance(tasks, dict): return p + ["NO_TASKS"]', 'if not isinstance(tasks, dict): return p'),
  ('if m.group(1) in out: raise ValueError', 'if False: raise ValueError'),
  ('if not out: raise ValueError("no tasks parsed")', 'pass'),
  ('INDEPENDENTLY_VERIFIED 0 (no reviewer', 'INDEPENDENTLY_VERIFIED 1 (no reviewer'),
 ]),
 ("horizon/assurance/durable.py", [
  ('if p != prev or h != self._h(prev, kind, subject, d): raise', 'if False: raise'),
  ('if p != prev or h', 'if h'),
  ('c.execute("BEGIN IMMEDIATE"); reg, _ = self._replay(c); st = reg.status(claim_id, epoch_now)', 'reg, _ = self._replay(c); st = reg.status(claim_id, epoch_now)'),
  ('if st[0] != "VALID": c.execute("COMMIT"); return False, st[1] or st[0]', 'if False: pass'),
  ('self._append(c, "PERMIT", claim_id, {"epoch": epoch_now}); c.execute("COMMIT"); return True, ""', 'c.execute("COMMIT"); return True, ""'),
  ('except Exception as e: return "REVOKED", "fail_closed:"', 'except Exception as e: return "VALID", "fail_closed:"'),
  ('except Exception as e: return False, "fail_closed:"', 'except Exception as e: return True, "fail_closed:"'),
  ('pub = self.trust.resolve(d["kid"], CLAIM_ISSUER_ROLE); pub.verify(bytes.fromhex(d["sig"]), _canon(d["body"]))', 'pass'),
  ('pub = self.trust.resolve(d["kid"], CLAIM_ISSUER_ROLE); pub.verify(', 'pub = None; _x = (lambda *a: None)(') if False else ('self.trust.resolve(d["kid"], CLAIM_ISSUER_ROLE)', 'self.trust.resolve(d["kid"], "reproducer")'),
  ('if subject not in permanent: reg.invalid.pop(subject, None)', 'reg.invalid.pop(subject, None)'),
  ('if subject in reg.claims: reg.revoke(subject); permanent.add(subject)', 'if subject in reg.claims: reg.revoke(subject)'),
  ('or a["kid"] == issued.get(subject, None) or subject not in issued: continue', ': pass'),
  ('self.trust.resolve(a["kid"], role).verify(bytes.fromhex(a["sig"]), _canon(a["body"]))', 'pass'),
  ('if a["body"]["claim_id"] != subject', 'if False'),
  ('if reason not in INVALIDATION_REASONS: raise', 'if False: raise'),
  ('if not evidence: raise', 'if False: raise'),
  ('if set(binding) != set(BINDING_FIELDS) or', 'if'),
  ('if signer.iss != CLAIM_ISSUER_ROLE: raise', 'if False: raise'),
  ('return row[0] == h' if False else 'return bool(row) and row[0] == h', 'return bool(row)'),
  ('return "EXTERNALLY_AUDITED" if "EXTERNALLY_AUDITED" in s else "INDEPENDENTLY_REPRODUCED" if "INDEPENDENTLY_REPRODUCED" in s else "SOURCE_VERIFIED"', 'return "EXTERNALLY_AUDITED" if s else "SOURCE_VERIFIED"'),
 ]),
 ("horizon/authz/effect.py", [
  ('if b64e(b) != s: raise EffectError("MALFORMED", "non-canonical base64url")', 'pass'),
  ('except ValueError: raise EffectError("MALFORMED", "bad base64url") from None\n    if b64e', 'except ValueError: raise\n    if b64e'),
 ]),
 ("horizon/ops/audience.py", [
  ('if _b64(b) != s: raise AuthError("MALFORMED", "non-canonical base64url")', 'pass'),
  ('except ValueError: raise AuthError("MALFORMED", "bad base64url") from None', 'except ValueError: raise'),
 ]),
 ("horizon/effects/mcp_gateway.py", [
  ('if not self._policy_allows(path): return', 'if False: return'),
  ('return os.path.dirname(real) == self.root and not os.path.basename(real).startswith(".") and real == os.path.abspath(path)', 'return True'),
  ('and not os.path.basename(real).startswith(".")', ''),
  ('and real == os.path.abspath(path)', ''),
  ('and set(a) == {"path", "content", "effect_id"}', ''),
  ('isinstance(a["content"], str)', 'True'),
  ('if p.get("name") != "write_file": return', 'if False: return'),
  ('ok = r["status"] == "ALLOW_COMMITTED"', 'ok = True'),
  ('if i is None: return None', 'pass'),
 ]),
 ("horizon/effects/filesink.py", [
  ('if r.get("prev") != prev or r.get("h") != self._rec_hash(prev, r): return False, n, prev', 'if False: return False, n, prev'),
  ('if r.get("prev") != prev or r.get("h") != self._rec_hash(prev, r): return False\n', 'if False: return False\n'),
  ('return hashlib.sha256(prev.encode() + json.dumps({k: v for k, v in rec.items() if k not in ("prev", "h")}', 'return hashlib.sha256(json.dumps({k: v for k, v in rec.items() if k not in ("prev", "h")}'),
  ('if i == n: return prev == head', 'if i == n: return True'),
  ('if n == 0: return head == prev', 'if n == 0: return True'),
  ('last = self._records()[-1:] ; prev = last[0].get("h", "") if last else "0" * 64', 'prev = "0" * 64'),
  ('self._append({"fence": effect_id, "ts": time.time()})', 'open(self.journal, "a").write(json.dumps({"fence": effect_id}) + "\\n")'),
 ]),
 ("horizon/effects/filesink.py", [
  ('if not ok:\n                if self.ledger.state(effect_id) == "REQUESTED": self.ledger.block', 'if False:\n                if self.ledger.state(effect_id) == "REQUESTED": self.ledger.block'),
  ('except Exception: ok, why = False, "GATE_ERROR"', 'except Exception: ok, why = True, "GATE_ERROR"'),
  ('ok = bool(g[0]) and g[0] is True;', 'ok = bool(g[0]);'),
  ('return {"status": "BLOCKED", "code": "ASSURANCE_DENIED", "why": why}', 'pass'),
 ]),
]
def run():
    try: return subprocess.run([sys.executable, "-B", "-W", "ignore", "-m", "unittest", "discover", "-s", "tests/blueprint", "-t", "."], capture_output=True, timeout=180, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", MUTATION_RUN="1")).returncode
    except subprocess.TimeoutExpired: return 1
assert run() == 0, "baseline red"
surv = []; n = 0
for F, muts in M:
    for a, b in muts:
        n += 1; src = open(F).read()
        if a not in src: surv.append(("MISSING", F, a)); continue
        try:
            open(F, "w").write(src.replace(a, b, 1))
            if run() == 0: surv.append(("SURVIVED", F, a))
        finally: open(F, "w").write(src)
print(f"{n - len(surv)}/{n} killed"); [print(s) for s in surv]; sys.exit(1 if surv else 0)
