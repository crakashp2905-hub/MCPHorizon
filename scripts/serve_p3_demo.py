#!/usr/bin/env python3
"""Start a demo service on a Unix socket with a SYNTHETIC policy and synthetic tokens (no real credentials). Used by TS SDK smoke test and examples."""
import os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.p3.test_service import TOK, POLICY, art
from horizon.service.core import Service
from horizon.service import http as H
d = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp()
s = Service(TOK, os.path.join(d, "audit.jsonl"), b"demo-key-not-secret-0000000000000", trace_path=os.path.join(d, "trace.jsonl"))
s.handle("POST", "/v2/policies", "adm", {"policy": POLICY}); s.handle("POST", "/v2/artifacts", "ta", {"artifact": art("a1")})
srv = H.serve(s, unix_path=os.path.join(d, "h.sock")); print("READY", os.path.join(d, "h.sock"), flush=True); srv.serve_forever()
