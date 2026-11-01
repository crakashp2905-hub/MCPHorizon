"""Real Chromium harness (P51-03, 04, 05, 06, 09, 12). Optional: needs Python playwright + Chromium (the unit tests skip it with an UNSUPPORTED message otherwise).
Everything is loopback: three synthetic origins (app = 127.0.0.1, evil = localhost, ads = 127.0.0.2), Chromium started with --no-proxy-server and a route handler that aborts any non-loopback request.
Trusted binding comes from the browser through the DevTools protocol, not from page script:
  * hit-test:           DOM.getNodeForLocation (browser hit-testing: pointer-events honoured, opacity ignored) -> backend node + owning frame id
  * frame origin:       Page.getFrameTree securityOrigin
  * element semantics:  read in an ISOLATED WORLD (own JS prototypes, so page script cannot replace getAttribute/FormData) through Element.prototype.getAttribute, resolving URLs with the document base
  * effect:             derived from that (a[href] -> NAVIGATE, form submit -> SUBMIT, multipart/file -> UPLOAD); script-initiated fetch/XHR/window.open have no declarative effect and are NOT derivable (UNKNOWN by design)
The 'screenshot-driven agent' perception is a DOM-side proxy for pixels (visible text and computed opacity); it is not a vision model.
Ground truth = what the synthetic servers received."""
import http.server, json, os, tempfile, threading, time
from urllib.parse import urlsplit
from . import core as C, guard as G
from .world import CANARY, violations, completed

LOOP = ("127.0.0.1", "localhost", "127.0.0.2")

class Lab:
    def __init__(self):
        self.log, self.pages, self.t0, self.servers, self.lk = [], {}, 0.0, [], threading.Lock()
        lab = self
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _rec(self, body=b""):
                host = self.headers.get("Host", ""); mode = self.headers.get("Sec-Fetch-Mode", ""); dest = self.headers.get("Sec-Fetch-Dest", "")
                with lab.lk: lab.log.append({"host": host, "method": self.command, "path": urlsplit(self.path).path, "ctype": self.headers.get("Content-Type", ""), "canary": CANARY.encode() in body or CANARY in self.path, "len": len(body), "fetch_mode": mode, "fetch_dest": dest, "user": self.headers.get("Sec-Fetch-User", "")})
            def do_GET(self):
                self._rec(); key = (self.headers.get("Host", ""), urlsplit(self.path).path); html = lab.pages.get(key)
                self.send_response(200 if html is not None else 404); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers(); self.wfile.write((html or "<p>not found</p>").encode())
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0) or 0); body = self.rfile.read(n) if n else b""; self._rec(body)
                self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(b"<p>received</p>")
        for name, host in (("app", "127.0.0.1"), ("ads", "127.0.0.2")):
            s = http.server.ThreadingHTTPServer((host, 0), H); setattr(self, name, "http://%s:%d" % (host, s.server_address[1])); self.servers.append(s)
        s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); self.evil = "http://localhost:%d" % s.server_address[1]; self.servers.append(s)
        for s in self.servers: threading.Thread(target=s.serve_forever, daemon=True).start()
    def put(self, origin, path, html): self.pages[(urlsplit(origin).netloc, path)] = html
    def mark(self): 
        with self.lk: self.log = []
    def effects(self):
        """Receiver-side classification of what arrived after mark(): the oracle's view."""
        out = []
        with self.lk: L = list(self.log)
        for r in L:
            dest = "http://" + r["host"]
            if r["method"] == "POST": kind = "UPLOAD" if "multipart" in r["ctype"] else "SUBMIT"
            elif r["fetch_dest"] == "document" and r["user"] == "?1": kind = "NAVIGATE"
            else: continue
            out.append({"kind": kind, "dest": dest, "data": "canary" if r["canary"] else "plain", "resource": r["path"]})
        return out
    def close(self):
        for s in self.servers: s.shutdown(); s.server_close()

ISOLATED_JS = """function(){
 const el=this, A=(n,a)=>Element.prototype.getAttribute.call(n,a), base=document.baseURI, abs=u=>{try{return new URL(u,base)}catch(e){return null}};
 const tag=el.tagName.toLowerCase(), type=(A(el,'type')||'').toLowerCase(), role=A(el,'role')||'', form=el.form||el.closest('form');
 let kind='NONE', u=null;
 if(tag==='a'&&A(el,'href')!==null){kind='NAVIGATE'; u=abs(A(el,'href'));}
 else if(type==='file'&&form){kind='UPLOAD'; u=abs(A(form,'formaction')||A(form,'action')||document.URL);}
 else if(form&&((tag==='button'&&(type===''||type==='submit'))||(tag==='input'&&(type==='submit'||type==='image')))){
   u=abs(A(el,'formaction')||A(form,'action')||document.URL); kind=((A(form,'enctype')||'').indexOf('multipart')>=0)?'UPLOAD':'SUBMIT';}
 const entries=[]; if(form){ try{ for(const [k,v] of new FormData(form).entries()) entries.push([k, (typeof v==='string')?v:('file:'+v.name)]); }catch(e){} }
 return {tag,type,role,id:A(el,'id')||'',kind,dest:u?u.origin:null,resource:u?u.pathname:null,entries};}"""
MAIN_REPORTED_JS = """function(){ const f=this.form||this.closest('form'); try{ const a=f&&f.action; return (typeof a==='string')?a:(a&&a.value)||null }catch(e){return null} }"""
PERCEIVE_JS = """(label)=>{ const out=[]; for(const e of document.querySelectorAll('body *')){ const t=(e.innerText||e.value||'').trim(); if(t!==label) continue; const cs=getComputedStyle(e); if(parseFloat(cs.opacity)<=0||cs.visibility==='hidden') continue; const r=e.getBoundingClientRect(); out.push({id:e.id,x:Math.round(r.left+r.width/2),y:Math.round(r.top+r.height/2)}); } return out.length?out[out.length-1]:null }"""
VISUAL_JS = """([x,y])=>{ for(const e of document.elementsFromPoint(x,y)){ const cs=getComputedStyle(e); if(parseFloat(cs.opacity)>0&&cs.visibility!=='hidden') return {id:e.id,text:(e.innerText||e.value||'').trim()}; } return null }"""

class Probe:
    """Trusted binding for the element at a point, read through DevTools."""
    def __init__(self, ctx, page): self.cdp = ctx.new_cdp_session(page); self.page = page; self.cdp.send("DOM.enable"); self.cdp.send("Page.enable"); self.cdp.send("Runtime.enable")
    def frames(self):
        out = {}; 
        def walk(t): out[t["frame"]["id"]] = t["frame"]["securityOrigin"]; [walk(c) for c in t.get("childFrames", [])]
        t = self.cdp.send("Page.getFrameTree")["frameTree"]; walk(t); return out, t["frame"]["securityOrigin"]
    def describe(self, backend, frame_id, tab="t1"):
        fr, top = self.frames(); ctx = self.cdp.send("Page.createIsolatedWorld", {"frameId": frame_id, "worldName": "hg-%d" % time.perf_counter_ns()})["executionContextId"]
        obj = self.cdp.send("DOM.resolveNode", {"backendNodeId": backend, "executionContextId": ctx})["object"]["objectId"]
        r = self.cdp.send("Runtime.callFunctionOn", {"objectId": obj, "functionDeclaration": ISOLATED_JS, "returnByValue": True})["result"]["value"]
        main = self.cdp.send("DOM.resolveNode", {"backendNodeId": backend})["object"]["objectId"]
        rep = self.cdp.send("Runtime.callFunctionOn", {"objectId": main, "functionDeclaration": MAIN_REPORTED_JS, "returnByValue": True})["result"].get("value")
        return r, fr.get(frame_id), top, rep, script_handled(self.cdp, main)
    def at(self, x, y, file=None):
        n = self.cdp.send("DOM.getNodeForLocation", {"x": x, "y": y, "includeUserAgentShadowDOM": False, "ignorePointerEventsNone": False}); return self.bind(n["backendNodeId"], n["frameId"], file)
    def bind(self, backend, frame_id, file=None):
        r, forigin, top, rep, sh = self.describe(backend, frame_id); vals = " ".join(v for _, v in r["entries"]) + " " + (os.path.basename(file[0]) if file else "") + (" " + file[1] if file else "")
        eff = {"kind": r["kind"], "dest": r["dest"], "resource": r["resource"], "data": ("canary" if CANARY in vals else ("plain" if vals.strip() else "none")) if r["kind"] != "NONE" else "none"} if r["kind"] != "NONE" else {"kind": "NONE", "dest": None, "data": "none", "resource": None}
        if sh: eff = {"kind": "NONE", "dest": None, "data": "none", "resource": None}
        rp = dict(eff); 
        if rep is not None: 
            try: u = urlsplit(rep); rp["dest"] = "%s://%s" % (u.scheme, u.netloc) if u.netloc else rp["dest"]; rp["resource"] = u.path or rp["resource"]
            except ValueError: pass
        el = C.element_digest(r["tag"], r["type"], r["role"], {k: eff[k] for k in ("kind", "dest", "resource")} if eff["kind"] != "NONE" else None, forigin)
        return {"tab": "t1", "frame": frame_id, "frame_origin": forigin, "top_origin": top, "element": {"id": r["id"], "digest": el}, "effect": eff, "reported": rp, "input_digest": C.digest(r["entries"]), "page_version": 0, "instrumented": True, "script_handled": sh}
    def by_selector(self, sel):
        doc = self.cdp.send("DOM.getDocument", {"depth": 0})["root"]["nodeId"]; n = self.cdp.send("DOM.querySelector", {"nodeId": doc, "selector": sel})["nodeId"]
        if not n: return None
        d = self.cdp.send("DOM.describeNode", {"nodeId": n})["node"]; return d["backendNodeId"], self.frames_main()
    def frames_main(self): return self.cdp.send("Page.getFrameTree")["frameTree"]["frame"]["id"]

CLICKY = {"click", "mousedown", "mouseup", "pointerdown", "pointerup", "submit", "auxclick"}
ANCESTORS_JS = """function(){ const out=[this]; const f=this.form||this.closest('form'); if(f) out.push(f); let n=this.parentElement; while(n){ out.push(n); n=n.parentElement; } out.push(document); return out }"""
def script_handled(cdp, main_obj):
    """True when script listens for click-like events on the element, its form or any ancestor: the effect may be initiated by script, which has no declarative form to derive."""
    arr = cdp.send("Runtime.callFunctionOn", {"objectId": main_obj, "functionDeclaration": ANCESTORS_JS, "returnByValue": False})["result"]["objectId"]
    for pr in cdp.send("Runtime.getProperties", {"objectId": arr, "ownProperties": True})["result"]:
        v = pr.get("value")
        if pr["name"].isdigit() and v and v.get("objectId"):
            if any(l["type"] in CLICKY for l in cdp.send("DOMDebugger.getEventListeners", {"objectId": v["objectId"]})["listeners"]): return True
    return False

def available():
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p: b = p.chromium.launch(args=["--no-proxy-server"]); v = b.version; b.close(); return v
    except Exception: return None

def chromium_args(): return ["--no-proxy-server"]
