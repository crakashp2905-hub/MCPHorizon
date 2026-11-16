"""K6: local, read-only web dashboard. Loopback only, no JavaScript, no external assets (works offline), strict CSP, every dynamic value HTML-escaped. Each run shows its bundle's signature/receipt verification, what landed, what was blocked and the recorded UNKNOWNs/limits.
It reads bundles from HOME and verifies them with the PUBLIC trust; it never signs, writes or executes anything. CANDIDATE: no authentication (loopback + same-user is the boundary), do not expose it."""
from __future__ import annotations
import html, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from horizon.product import home as H

CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
CSS = "body{font:15px system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:.35rem .5rem;text-align:left;vertical-align:top}.ok{color:#0a6b2c}.bad{color:#b00020;font-weight:600}.unk{color:#8a5a00}code{background:#f3f3f3;padding:0 .25rem}"


def e(x) -> str: return html.escape(str(x), quote=True)
def page(title, body) -> bytes: return f"<!doctype html><html lang=en><meta charset=utf-8><title>{e(title)}</title><style>{CSS}</style><body>{body}</body></html>".encode()


def make_handler(home: H.Home):
    tr = home.trust()
    class Hd(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, code, data, ctype="text/html; charset=utf-8"):
            self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Security-Policy", CSP); self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Cache-Control", "no-store"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
        def _row(self, rid):
            try: d = home.load_bundle(rid); v = H.verify_bundle(d, tr); b = d["body"]; return rid, v, b
            except Exception: return rid, {"ok": False, "checks": {}}, None
        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/":
                rows = []
                for rid in reversed(home.run_ids()):
                    rid, v, b = self._row(rid); land = sum(1 for c in (b or {}).get("changes", []) if c["status"] == "ALLOW_COMMITTED"); blk = sum(1 for c in (b or {}).get("changes", []) if c["status"] in ("BLOCKED", "WOULD_BLOCK"))
                    rows.append(f"<tr><td><a href='/run/{e(rid)}'>{e(rid)}</a></td><td>{e((b or {}).get('mode', '?'))}</td><td>{e((b or {}).get('profile', {}).get('name', '?'))}</td><td>{land}</td><td>{blk}</td><td class='{'ok' if v['ok'] else 'bad'}'>{'verified' if v['ok'] else 'VERIFICATION FAILED'}</td></tr>")
                return self._send(200, page("hzd runs", f"<h1>hzd evidence</h1><p>Read-only. CANDIDATE. Verification uses the public key only.</p><table><tr><th>run</th><th>mode</th><th>profile</th><th>landed</th><th>blocked</th><th>bundle</th></tr>{''.join(rows) or '<tr><td colspan=6>no runs yet</td></tr>'}</table>"))
            if path == "/api/runs.json":
                out = []
                for rid in home.run_ids(): rid, v, b = self._row(rid); out.append({"run_id": rid, "verified": v["ok"], "mode": (b or {}).get("mode")})
                return self._send(200, json.dumps(out).encode(), "application/json")
            if path.startswith("/run/"):
                rid = path[5:]
                try: rid, v, b = self._row(rid)
                except Exception: return self._send(404, page("not found", "not found"))
                if b is None: return self._send(404, page("not found", "not found"))
                ch = "".join(f"<tr><td><code>{e(c['path'])}</code></td><td>{e(c['op'])}</td><td class='{'ok' if c['status'] in ('ALLOW_COMMITTED', 'WOULD_ALLOW') else 'bad'}'>{e(c['status'])}</td><td>{e(c.get('code') or '')}</td><td>{'signed receipt' if c.get('receipt_v1') else ''}</td></tr>" for c in b["changes"])
                chk = "".join(f"<li>{e(k)}: <span class='{'ok' if x is True else 'bad' if x is False else ''}'>{e(x)}</span></li>" for k, x in v["checks"].items())
                body = (f"<p><a href='/'>&larr; runs</a></p><h1>{e(rid)}</h1><p class='{'ok' if v['ok'] else 'bad'}'>{'Signature and receipts verified' if v['ok'] else 'VERIFICATION FAILED — do not trust this bundle'}</p><ul>{chk}</ul>"
                        f"<p>mode <b>{e(b['mode'])}</b>, profile <b>{e(b['profile']['name'])}</b>, allow {e(b['profile']['allow_globs'])}, agent exit {e(b['runner']['agent_exit'])}, confined {e(b['runner']['confined'])}</p><table><tr><th>path</th><th>op</th><th>status</th><th>code</th><th>evidence</th></tr>{ch}</table>"
                        f"<h2>Journal</h2><p>chain ok: {e(b['journal']['chain_ok'])}, records {e(b['journal']['records'])}</p><h2 class='unk'>Not observed / limits</h2><ul>{''.join('<li>' + e(x) + '</li>' for x in b['limits'])}</ul>")
                return self._send(200, page(rid, body))
            return self._send(404, page("not found", "not found"))
        def do_POST(self): return self._send(405, page("method not allowed", "read-only"))
        do_PUT = do_DELETE = do_PATCH = do_POST
    return Hd


def serve(home: H.Home, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "::1", "localhost"): raise H.ProductError("NON_LOOPBACK_REFUSED", "the dashboard has no authentication and binds to loopback only")
    home.require_init(); return ThreadingHTTPServer((host, port), make_handler(home))
