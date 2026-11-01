#!/usr/bin/env python3
"""P50-15 overhead: reservation throughput and tail latency of the SQLite ledger on this machine. Machine-specific, so it is NOT part of the deterministic results; prints JSON, writes nothing."""
import json, os, platform, sys, tempfile, threading, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.hpolicy.authority import HorizonPolicy
from horizon.budget import ledger as L, units as U


def mk(path):
    A = HorizonPolicy("pol-1", clock=time.time); ow = A.register_issuer("owner", {"ATTESTATION"}); c = {"type": "budget", "task": "T", "limits": {"requests": 10 ** 9}, "rev": 3}
    led = L.Ledger(path, A.verifier(), time.time); led.open_task(ow.issue("ATTESTATION", principal="lead", artifact="T", args_digest=U.digest(c), claim=c, ttl=10 ** 6)); return A, led


def pct(xs, p): xs = sorted(xs); return round(xs[min(len(xs) - 1, int(len(xs) * p))] * 1000, 3)
def cycle(led, i, lat):
    t = time.perf_counter(); led.reserve("T", "lead", "r%s" % i, "d", {"requests": 1}); led.start("r%s" % i); led.commit("r%s" % i, {"requests": 1}); lat.append(time.perf_counter() - t)


def main(n=int(os.environ.get("N", "500"))):
    out = {"machine": platform.platform(), "python": platform.python_version(), "n": n}
    for name, path in (("memory", ":memory:"), ("file", os.path.join(tempfile.mkdtemp(), "l.db"))):
        A, led = mk(path); lat = []; t0 = time.perf_counter()
        for i in range(n): cycle(led, i, lat)
        dt = time.perf_counter() - t0; out[name + "_single_thread"] = {"cycles_per_s": round(n / dt, 1), "p50_ms": pct(lat, .5), "p99_ms": pct(lat, .99)}
    A, led = mk(os.path.join(tempfile.mkdtemp(), "c.db")); lat = []; ths = []; t0 = time.perf_counter()
    for k in range(8): ths.append(threading.Thread(target=lambda k=k: [cycle(led, "%d-%d" % (k, i), lat) for i in range(n // 8)]))
    [t.start() for t in ths]; [t.join() for t in ths]; dt = time.perf_counter() - t0; out["file_8_threads"] = {"cycles_per_s": round(len(lat) / dt, 1), "p50_ms": pct(lat, .5), "p99_ms": pct(lat, .99)}
    out["note"] = "one cycle = reserve + start + commit (three transactions). Single SQLite writer: throughput is bounded by commit latency; no horizontal scaling is claimed."
    print(json.dumps(out, indent=1))


main()
