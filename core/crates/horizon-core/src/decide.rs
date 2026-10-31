//! Pre-effect policy evaluation with deny precedence. Mirrors horizon/core/decide.py.
use crate::labels::conf_rank;
use serde_json::{json, Value};

const WHEN_KEYS: [&str; 8] = ["effect", "sink_zone", "input_label_at_least", "maximum_input_label", "authorized_flow", "lineage_complete", "purpose", "unknown_effect_or_destination"];

fn b(ctx: &Value, k: &str) -> bool { ctx[k].as_bool().unwrap_or(false) }

pub fn rule_matches(when: &Value, ctx: &Value) -> bool {
    let Some(w) = when.as_object() else { return false };
    if w.is_empty() || w.keys().any(|k| !WHEN_KEYS.contains(&k.as_str())) { return false; }
    let label = conf_rank(ctx["input_label"].as_str().unwrap_or("PUBLIC")).unwrap_or(0);
    for (k, want) in w {
        let ok = match k.as_str() {
            "effect" => ctx["effect"] == *want,
            "sink_zone" => ctx.get("sink_zone").unwrap_or(&Value::Null) == want,
            "purpose" => ctx.get("purpose").unwrap_or(&Value::Null) == want,
            "input_label_at_least" => label >= conf_rank(want.as_str().unwrap_or("")).unwrap_or(usize::MAX),
            "maximum_input_label" => label <= conf_rank(want.as_str().unwrap_or("")).unwrap_or(0),
            "authorized_flow" => want.as_bool() == Some(b(ctx, "authorized_flow")),
            "lineage_complete" => want.as_bool() == Some(b(ctx, "lineage_complete")),
            "unknown_effect_or_destination" => want.as_bool() == Some(!b(ctx, "mapping_complete")),
            _ => false,
        };
        if !ok { return false; }
    }
    true
}

fn out(v: &str, codes: &[&str], rule: Option<&str>) -> Value { json!({"verdict": v, "reason_codes": codes, "rule": rule}) }

pub fn decide(policy: &Value, ctx: &Value) -> Value {
    let mut rules: Vec<&Value> = policy["rules"].as_array().unwrap().iter().collect();
    rules.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let d = &policy["defaults"];
    if !b(ctx, "identity_valid") { return out("DENY", &["INVALID_IDENTITY"], None); }
    if !b(ctx, "interceptable") { return out("DENY", &["UNINTERCEPTABLE_EFFECT"], None); }
    let (mut deny, mut review, mut allow, mut quar, mut unk): (Vec<&str>, Vec<&str>, Vec<&str>, Vec<&str>, Vec<&str>) = Default::default();
    for r in &rules {
        if rule_matches(&r["when"], ctx) {
            let id = r["id"].as_str().unwrap();
            match r["decision"].as_str().unwrap() { "DENY" => deny.push(id), "REVIEW" => review.push(id), "ALLOW" => allow.push(id), "QUARANTINE" => quar.push(id), "UNKNOWN" => unk.push(id), _ => {} }
        }
    }
    if let Some(r) = deny.first() { return out("DENY", &["HARD_POLICY_PROHIBITION"], Some(r)); }
    let protected = b(ctx, "protected_effect");
    if !b(ctx, "mapping_complete") {
        return if protected { out("DENY", &["UNKNOWN_MAPPING_PROTECTED"], None) } else { out("UNKNOWN", &["UNKNOWN_MAPPING"], None) };
    }
    let approved = ctx.get("approval").and_then(|a| a.get("valid")).and_then(|v| v.as_bool()).unwrap_or(false);
    if let Some(r) = review.first() { if !approved { return out("REVIEW", &["REVIEW_REQUIRED"], Some(r)); } }
    if let Some(r) = allow.first() {
        if !b(ctx, "lineage_complete") && protected { return out("REVIEW", &["INCOMPLETE_LINEAGE"], Some(r)); }
        return if review.is_empty() { out("ALLOW", &["EXPLICIT_ALLOW"], Some(r)) } else { out("ALLOW", &["EXPLICIT_ALLOW", "APPROVED_REVIEW"], Some(r)) };
    }
    if let Some(r) = quar.first() { return out("QUARANTINE", &["POLICY_QUARANTINE"], Some(r)); }
    if let Some(r) = unk.first() { return out("UNKNOWN", &["POLICY_UNKNOWN"], Some(r)); }
    if protected { let v = d["protected_effect"].as_str().unwrap_or("DENY"); return out(v, &["DEFAULT_PROTECTED_EFFECT"], None); }
    out(d["inspection_only"].as_str().unwrap_or("QUARANTINE"), &["DEFAULT_INSPECTION_ONLY"], None)
}
