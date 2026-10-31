"""Canonical schema definitions (source of truth). `scripts/gen_schemas.py` writes schemas/*.schema.json."""
SCHEMA_MAJOR = 2
SD = "https://json-schema.org/draft/2020-12/schema"
SHA = {"type": "string", "pattern": r"sha256:[0-9a-f]{64}"}
ID = {"type": "string", "pattern": r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}"}   # ASCII only: no confusables
TS = {"type": "string", "pattern": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z"}
VERSION = {"type": "string", "pattern": r"\d{1,3}\.\d{1,3}\.\d{1,3}"}
ACTIONS = ["read", "list", "write", "modify", "delete", "execute", "send", "receive", "admin"]
CONF = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"]
TRUST = ["TRUSTED", "UNVERIFIED", "UNTRUSTED"]
PHASES = ["discover", "register", "before_call", "decision", "after_call", "tool_result", "artifact_produced",
          "artifact_consumed", "handoff", "verification", "declassification", "approval", "error", "cancel",
          "retry", "timeout", "policy_update"]
VERDICTS = ["ALLOW", "DENY", "REVIEW", "QUARANTINE", "UNKNOWN", "SHADOW_ALLOW"]
PROTOCOLS = ["mcp", "utcp", "code_mode", "a2a", "native"]
UNK = {"const": "unknown"}
LOGOP = {"type": "string", "pattern": r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+"}

EVENT = {
    "$schema": SD, "$id": "https://mcphorizon.invalid/schemas/event/2.0.0", "title": "Event", "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "event_id", "run_id", "principal_id", "principal_source", "source_protocol",
                 "protocol_version", "phase", "logical_operation", "native_operation", "target", "monotonic_seq",
                 "wall_time"],
    "properties": {
        "schema_version": VERSION, "event_id": ID, "run_id": ID, "trace_id": ID, "span_id": ID,
        "parent_event_id": {"type": ["string", "null"], "pattern": ID["pattern"]},
        "agent_id": ID, "principal_id": ID,
        "principal_source": {"enum": ["trusted_host_identity", "verified_token", "agent_claimed", "unknown"]},
        "source_protocol": {"enum": PROTOCOLS}, "protocol_version": {"type": "string", "minLength": 1, "maxLength": 32},
        "phase": {"enum": PHASES}, "logical_operation": LOGOP,
        "native_operation": {"type": "string", "minLength": 1, "maxLength": 256},
        "tool_id": {"type": "string", "maxLength": 256}, "tool_registry_digest": SHA,
        "target": {"type": "object", "additionalProperties": False, "required": ["kind", "canonical_id"],
                   "properties": {"kind": {"enum": ["resource", "url", "file", "process", "agent", "unknown"]},
                                  "canonical_id": {"type": "string", "minLength": 1, "maxLength": 2048}}},
        "args_digest": SHA,
        "inputs": {"type": "array", "maxItems": 256, "items": {
            "type": "object", "additionalProperties": False, "required": ["artifact_id"],
            "properties": {"artifact_id": ID, "label": {"enum": CONF + ["unknown"]}}}},
        "requested_effects": {"type": "array", "maxItems": 16, "items": {"enum": ACTIONS}},
        "authorization_ref": {"type": "string", "maxLength": 256},
        "policy_version": {"type": "string", "maxLength": 128}, "decision_id": ID,
        "monotonic_seq": {"type": "integer", "minimum": 0, "maximum": 9007199254740991},
        "wall_time": TS,
        "runtime_provenance": {"type": "object", "additionalProperties": False, "required": ["origin"],
                               "properties": {"origin": {"enum": ["trusted-adapter", "agent", "unknown"]},
                                              "sig_ref": {"type": "string", "maxLength": 256}}},
        "redactions": {"type": "array", "maxItems": 64, "items": {"type": "string", "maxLength": 128}},
    },
}

DECISION = {
    "$schema": SD, "$id": "https://mcphorizon.invalid/schemas/decision/2.0.0", "title": "Decision", "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "decision_id", "policy_version", "event_id", "verdict", "reason_codes", "mode"],
    "properties": {
        "schema_version": VERSION, "decision_id": ID, "policy_version": {"type": "string", "minLength": 1, "maxLength": 128},
        "event_id": ID, "verdict": {"enum": VERDICTS},
        "mode": {"enum": ["enforce", "shadow"]},
        "reason_codes": {"type": "array", "maxItems": 32, "items": {"type": "string", "pattern": r"[A-Z][A-Z0-9_]{1,63}"}},
        "horizon_witnesses": {"type": "array", "maxItems": 64, "items": {"type": "string", "maxLength": 256}},
        "required_approval": {"type": ["object", "null"]},
        "expires_at": TS, "approved_principal": ID,
        "bound_target_digest": SHA, "bound_args_digest": SHA, "idempotency_key": ID,
    },
}

CAPABILITY = {
    "$schema": SD, "$id": "https://mcphorizon.invalid/schemas/capability/2.0.0", "title": "Capability",
    "type": "object", "additionalProperties": False,
    "required": ["action", "resource_class", "scope", "principal_id", "labels"],
    "properties": {
        "action": {"enum": ACTIONS}, "resource_class": {"type": "string", "pattern": r"[a-z][a-z0-9_.-]{0,63}"},
        "resource_id": {"type": "string", "maxLength": 512},
        "scope": {"type": "object", "additionalProperties": False, "required": ["kind"],
                  "properties": {"kind": {"enum": ["literal", "glob", "tenant", "any"]},
                                 "value": {"type": "string", "maxLength": 512}}},
        "principal_id": ID,
        "constraints": {"type": "object", "additionalProperties": False, "properties": {
            "allowed_destinations": {"type": "array", "maxItems": 64, "items": {"type": "string", "maxLength": 512}},
            "max_records": {"type": "integer", "minimum": 0}, "purpose": {"type": "string", "maxLength": 128}}},
        "labels": {"type": "object", "additionalProperties": False, "required": ["confidentiality", "trust"],
                   "properties": {"confidentiality": {"enum": CONF}, "trust": {"enum": TRUST}}},
    },
}

ARTIFACT = {
    "$schema": SD, "$id": "https://mcphorizon.invalid/schemas/artifact/2.0.0", "title": "Artifact", "type": "object",
    "additionalProperties": False,
    "required": ["id", "producer_event_id", "parents", "confidentiality", "trust", "tenant_id", "partial_lineage"],
    "properties": {
        "id": ID, "content_digest": SHA, "producer_event_id": ID,
        "parents": {"type": "array", "maxItems": 1024, "items": ID, "uniqueItems": True},
        "confidentiality": {"enum": CONF}, "trust": {"enum": TRUST},
        "purpose_tags": {"type": "array", "maxItems": 32, "items": {"type": "string", "maxLength": 64}},
        "tenant_id": ID, "retention_class": {"type": "string", "maxLength": 64},
        "partial_lineage": {"type": "boolean"},
    },
}

LINEAGE_EDGE = {
    "$schema": SD, "$id": "https://mcphorizon.invalid/schemas/lineage_edge/2.0.0", "title": "LineageEdge",
    "$defs": {
        "produces": {"type": "object", "additionalProperties": False, "required": ["kind", "event_id", "artifact_id"],
                     "properties": {"kind": {"const": "produces"}, "event_id": ID, "artifact_id": ID}},
        "consumes": {"type": "object", "additionalProperties": False, "required": ["kind", "event_id", "artifact_id"],
                     "properties": {"kind": {"const": "consumes"}, "event_id": ID, "artifact_id": ID}},
        "derives": {"type": "object", "additionalProperties": False,
                    "required": ["kind", "from_artifact", "to_artifact", "transformation_id"],
                    "properties": {"kind": {"const": "derives"}, "from_artifact": ID, "to_artifact": ID, "transformation_id": ID}},
        "verifies": {"type": "object", "additionalProperties": False,
                     "required": ["kind", "verifier_event_id", "artifact_id", "verification_kind", "authority", "scope"],
                     "properties": {"kind": {"const": "verifies"}, "verifier_event_id": ID, "artifact_id": ID,
                                    "verification_kind": {"type": "string", "maxLength": 64},
                                    "authority": ID, "scope": {"type": "string", "minLength": 1, "maxLength": 256}}},
    },
    "oneOf": [{"$ref": "#/$defs/produces"}, {"$ref": "#/$defs/consumes"}, {"$ref": "#/$defs/derives"}, {"$ref": "#/$defs/verifies"}],
}

WHEN_KEYS = {"effect": {"enum": ACTIONS}, "sink_zone": {"type": "string", "pattern": r"[a-z][a-z0-9_]{0,63}"},
             "input_label_at_least": {"enum": CONF}, "maximum_input_label": {"enum": CONF},
             "authorized_flow": {"type": "boolean"}, "lineage_complete": {"type": "boolean"},
             "purpose": {"type": "string", "pattern": r"[a-z][a-z0-9_]{0,63}"},
             "unknown_effect_or_destination": {"type": "boolean"}}
POLICY = {
    "$schema": SD, "$id": "https://mcphorizon.invalid/schemas/policy/1.0.0", "title": "PolicyBundle",
    "type": "object", "additionalProperties": False,
    "required": ["apiVersion", "kind", "metadata", "rules", "defaults"],
    "properties": {
        "apiVersion": {"const": "horizon.security/v2"}, "kind": {"const": "PolicyBundle"},
        "metadata": {"type": "object", "additionalProperties": False, "required": ["id", "version", "owner", "signature"],
                     "properties": {"id": ID, "version": {"type": "integer", "minimum": 1}, "owner": ID,
                                    "signature": {"type": "string", "minLength": 1, "maxLength": 512}}},
        "principals": {"type": "array", "maxItems": 1000, "items": {
            "type": "object", "additionalProperties": False, "required": ["id"],
            "properties": {"id": ID, "allowed_purposes": {"type": "array", "maxItems": 64,
                                                        "items": {"type": "string", "pattern": r"[a-z][a-z0-9_]{0,63}"}}}}},
        "resources": {"type": "array", "maxItems": 1000, "items": {
            "type": "object", "additionalProperties": False, "required": ["match", "confidentiality"],
            "properties": {"match": {"type": "object", "additionalProperties": False, "required": ["class"],
                                     "properties": {"class": {"type": "string", "pattern": r"[a-z][a-z0-9_.-]{0,63}"}}},
                           "confidentiality": {"enum": CONF}}}},
        "rules": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {
            "type": "object", "additionalProperties": False, "required": ["id", "when", "decision"],
            "properties": {"id": ID, "when": {"type": "object", "additionalProperties": False, "properties": WHEN_KEYS},
                           "decision": {"enum": [v for v in VERDICTS if v != "SHADOW_ALLOW"]}}}},
        "defaults": {"type": "object", "additionalProperties": False,
                     "required": ["protected_effect", "inspection_only", "evaluation_timeout"],
                     "properties": {"protected_effect": {"const": "DENY"}, "inspection_only": {"enum": ["QUARANTINE", "DENY"]},
                                    "evaluation_timeout": {"const": "DENY"}}},
    },
}

ALL = {"event": EVENT, "decision": DECISION, "capability": CAPABILITY, "artifact": ARTIFACT,
       "lineage_edge": LINEAGE_EDGE, "policy": POLICY}


def _anchor(node):
    """Make every pattern ECMA/Rust/Python-consistent: ASCII digits only, fully anchored (JSON Schema patterns are unanchored)."""
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if k == "pattern" and isinstance(v, str):
                v = v.replace("\\d", "[0-9]")
                node[k] = v if v.startswith("^(?:") else "^(?:" + v + ")$"
            else:
                _anchor(v)
    elif isinstance(node, list):
        for v in node: _anchor(v)


for _s in ALL.values(): _anchor(_s)
