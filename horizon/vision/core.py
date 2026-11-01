"""Canonical UI action, trusted binding and derived effect (P51-01, 02, 05, 16).

Three objects, kept apart on purpose:
  ACTION  = what the agent proposes. Untrusted: pixel coordinates, the element the agent *believes* it is operating (`intent`, from its screenshot or snapshot), the element version it observed.
  BINDING = what the browser integration reports about the object that really receives the action: hit-tested element, frame, frame origin, effect resolved by the browser (form target, link target, picker, download, clipboard), element digest, input digest.
            Produced by privileged instrumentation, never by page script and never from screenshot text.
  EFFECT  = the protected effect derived from the binding: {kind, dest, data, resource}.
Pixel coordinates carry none of origin, element identity or semantics; they only select which object the browser hit-tests."""
import hashlib, json

def canonical(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def digest(o) -> str: return "sha256:" + hashlib.sha256(canonical(o)).hexdigest()

EFFECT_KINDS = ("NONE", "SUBMIT", "UPLOAD", "NAVIGATE", "DOWNLOAD", "CLIPBOARD")
PROTECTED = ("SUBMIT", "UPLOAD", "NAVIGATE", "DOWNLOAD", "CLIPBOARD")
DATA = ("none", "plain", "canary")                                                      # `canary` = the synthetic sensitive value TEST_CANARY_NOT_SECRET
OPS = ("click", "key", "tool_upload", "tool_download")

ACTION_SCHEMA = {"op": OPS, "x": "int|None", "y": "int|None", "intent": "element id the agent believes it targets (untrusted)", "observed": "element digest the agent observed (untrusted)", "tab": "str"}
BINDING_SCHEMA = {"tab": "str", "frame": "frame id from the browser frame tree", "frame_origin": "origin of the frame that owns the element (browser-reported)", "top_origin": "origin of the top-level document",
                  "element": {"id": "stable element identity", "digest": "digest(tag, type, role, resolved effect, frame origin)"}, "effect": "EFFECT", "reported": "what page script / DOM text claims (untrusted, kept only to measure spoofing)",
                  "input_digest": "digest of the form data at the time of the action", "page_version": "int", "instrumented": "bool"}
EFFECT_SCHEMA = {"kind": EFFECT_KINDS, "dest": "origin the browser will contact or write to", "data": DATA, "resource": "file / url path / clipboard label"}

def element_digest(tag, typ, role, eff, frame_origin) -> str: return digest([tag, typ, role, eff or {"kind": "NONE"}, frame_origin])
def envelope(op, element_digest_, eff, input_digest, top_origin, tab) -> dict: return {"op": op, "element": element_digest_, "effect": eff, "input": input_digest, "top": top_origin, "tab": tab}
def envelope_digest(env) -> str: return digest(env)
