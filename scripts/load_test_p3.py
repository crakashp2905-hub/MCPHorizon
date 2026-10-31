#!/usr/bin/env python3
"""P3-20 load test of the in-process decision path (bounded context). Prints MEASURED percentiles for THIS machine; nothing is hardcoded.
Usage: load_test_p3.py [N] [threads]"""
import json, os, sys, tempfile, threading, time, platform
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.p3.test_service import TOK, POLICY, art, req
from horizon.service.core import Service


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000; th = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    d = tempfile.mkdtemp(); s = Service(TOK, os.path.join(d, "a.jsonl"), b"k" * 32, rate=1e9, burst=10**9)
    s.handle("POST", "/v2/policies", "adm", {"policy": POLICY})
    for i in range(50): s.handle("POST", "/v2/artifacts", "ta", {"artifact": art(f"a{i}", parents=[f"a{i-1}"] if i else [])})
    lat, lock = [], threading.Lock()
    def w(k):
        loc = []
        for i in range(n // th):
            r = req(input_artifacts=[f"a{(i + k) % 50}"]); t = time.perf_counter(); st, _ = s.handle("POST", "/v2/decisions", "ta", r); loc.append(time.perf_counter() - t)
            assert st == 200
        with lock: lat.extend(loc)
    t0 = time.perf_counter(); ts = [threading.Thread(target=w, args=(k,)) for k in range(th)]; [t.start() for t in ts]; [t.join() for t in ts]; wall = time.perf_counter() - t0
    lat.sort(); q = lambda p: round(lat[min(len(lat) - 1, int(p * len(lat)))] * 1000, 3)
    print(json.dumps({"requests": len(lat), "threads": th, "wall_s": round(wall, 3), "throughput_rps": round(len(lat) / wall),
                      "p50_ms": q(.5), "p95_ms": q(.95), "p99_ms": q(.99), "max_ms": round(lat[-1] * 1000, 3),
                      "scope": "in-process Service.handle with audit write (no fsync), lineage depth <=50; excludes HTTP/socket overhead",
                      "machine": {"python": platform.python_version(), "cpu_count": os.cpu_count(), "platform": platform.platform()}}, indent=1))


main()
