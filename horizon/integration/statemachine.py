"""P54-11: concurrency / replay / retry state-machine checks across modules, run live against the real stores with an independent invariant check.
Each function returns {name, ok, detail}. Threads share one SQLite file through separate connections, as the module tests do."""
import os, shutil, tempfile, threading
from ..hpolicy.authority import HorizonPolicy
from ..budget import ledger as BL, units as BU, harness as BH
from ..privacy import ledger as PL, units as PU
from ..privacy.mechanisms import laplace_charge as LAP
from ..temporal.store import Store
from ..temporal import oracle as TO
from ..continuity import experiment as CE, scenarios as CS

def _par(n, fn):
    bar = threading.Barrier(n); out = [None] * n
    def w(i): bar.wait(); out[i] = fn(i)
    ts = [threading.Thread(target=w, args=(i,)) for i in range(n)]; [t.start() for t in ts]; [t.join() for t in ts]; return out

def budget_concurrent(n=16, limit=100, each=10, **kw):
    d = tempfile.mkdtemp(); t = [1000.0]; clk = lambda: t[0]; A = HorizonPolicy("pol-1", clock=clk); ow = A.register_issuer("owner", {"ATTESTATION"}); path = os.path.join(d, "l.db")
    c = {"type": "budget", "task": "T", "limits": {"compute_units": limit}, "rev": 3}; tok = ow.issue("ATTESTATION", principal="lead", artifact="T", args_digest=BU.digest(c), claim=c, ttl=10 ** 7, now=1000)
    led = BL.Ledger(path, A.verifier(), clk, **kw); led.open_task(tok)
    ok = _par(n, lambda i: BL.Ledger(path, A.verifier(), clk, **kw).reserve("T", "lead", "r%d" % i, "d", {"compute_units": each})["ok"])
    r = {"name": "budget: concurrent reserves never exceed the cap", "ok": sum(ok) == limit // each and led.invariants() == [] and led.verify_chain(), "detail": {"granted": sum(ok), "expected": limit // each}}; shutil.rmtree(d, ignore_errors=True); return r

def budget_retry_replay(**kw):
    d = tempfile.mkdtemp(); t = [1000.0]; clk = lambda: t[0]; A = HorizonPolicy("pol-1", clock=clk); ow = A.register_issuer("owner", {"ATTESTATION"})
    c = {"type": "budget", "task": "T", "limits": {"compute_units": 100}, "rev": 3}; led = BL.Ledger(os.path.join(d, "l.db"), A.verifier(), clk, **kw); led.open_task(ow.issue("ATTESTATION", principal="lead", artifact="T", args_digest=BU.digest(c), claim=c, ttl=10 ** 7, now=1000))
    a = led.reserve("T", "lead", "r1", "d", {"compute_units": 30}); b = led.reserve("T", "lead", "r1", "d", {"compute_units": 30}); other = led.reserve("T", "lead", "r1", "different-query", {"compute_units": 30})
    used = led.used("T"); r = {"name": "budget: a retried request id is charged once; a reused id with another query is refused", "ok": a["ok"] and b["ok"] and not other["ok"] and used.get("compute_units") == 30, "detail": {"used": used, "reuse_reason": other.get("reason")}}; shutil.rmtree(d, ignore_errors=True); return r

def privacy_concurrent(procs=8, per=30, **kw):
    d = tempfile.mkdtemp(); now = [1000.0]; A = HorizonPolicy("pol-1", clock=lambda: now[0]); ow = A.register_issuer("privacy-owner", {"ATTESTATION"}); lid = PU.ledger_id("d"); path = os.path.join(d, "p.db")
    c = {"type": "privacy-budget", "dataset": "d", "eps": "2", "delta": "1e-6", "accountant": "basic"}; tok = ow.issue("ATTESTATION", principal="owner", artifact=lid, args_digest=PL.digest(c), object_version=1, ttl=10 ** 8, claim=c, now=1000)
    PL.Ledger(path, A.verifier(), lambda: 1000.0, **kw).open_budget(tok)
    def work(i): lg = PL.Ledger(path, A.verifier(), lambda: 1000.0, **kw); return sum(lg.reserve(lid, "p%d-%d" % (i, k), "q", LAP("0.25", 1))["ok"] for k in range(per))
    got = sum(_par(procs, work)); l2 = PL.Ledger(path, A.verifier(), lambda: 1000.0)
    r = {"name": "privacy: concurrent reserves never exceed epsilon", "ok": got == 8 and l2.verify_chain() and l2.audit(lid) == [], "detail": {"granted": got, "expected": 8}}; shutil.rmtree(d, ignore_errors=True); return r

def temporal_cas(n=8):
    d = tempfile.mkdtemp(); p = os.path.join(d, "t.db"); t = [1.0]; a = Store(lambda: t[0], p); a.put_object("d", "PUBLIC", "x")
    won = _par(n, lambda i: Store(lambda: t[0], p).cas_update("d", 1, content="w%d" % i)); lost = [x for x in TO.judge(a) if x["reasons"] == ["LOST_UPDATE"]]
    r = {"name": "temporal: with CAS exactly one concurrent writer wins and no update is lost", "ok": sum(won) == 1 and a.obj("d")["version"] == 2 and not lost, "detail": {"winners": sum(won)}}; shutil.rmtree(d, ignore_errors=True); return r

def temporal_lww_control(n=4):
    """Negative control: last-writer-wins must LOSE updates; if it did not, the CAS check above would be vacuous."""
    d = tempfile.mkdtemp(); p = os.path.join(d, "t.db"); t = [1.0]; a = Store(lambda: t[0], p); a.put_object("d", "PUBLIC", "x")
    _par(n, lambda i: Store(lambda: t[0], p).lww_update("d", 1, content="w%d" % i)); lost = sum(1 for x in TO.judge(a) if x["reasons"] == ["LOST_UPDATE"])
    r = {"name": "temporal (control): last-writer-wins loses updates, so the oracle can see them", "ok": lost == n - 1, "detail": {"lost": lost}}; shutil.rmtree(d, ignore_errors=True); return r

def continuity_replay(system="continuity"):
    ex = [e for e in CE.systems() if e.name == system][0]; sc = [s for s in CS.SCENARIOS if s["id"] == "A08"][0]; r = CE.run_one(ex, sc)
    return {"name": "continuity: a replayed signed envelope is refused and spends the shared budget once", "ok": not r["violations"] and r["replay_status"] not in (None, "MIGRATED"), "detail": {"first": r["status"], "replay": r["replay_status"], "violations": r["violation_kinds"]}}

def continuity_dual_run(system="continuity"):
    ex = [e for e in CE.systems() if e.name == system][0]; sc = [s for s in CS.SCENARIOS if s["id"] == "A14"][0]; r = CE.run_one(ex, sc)
    return {"name": "continuity: a source that keeps running after migration is stopped (no double spend)", "ok": not r["violations"], "detail": {"status": r["status"], "violations": r["violation_kinds"]}}

ALL = [budget_concurrent, budget_retry_replay, privacy_concurrent, temporal_cas, temporal_lww_control, continuity_replay, continuity_dual_run]
def run_all(): return [f() for f in ALL]
