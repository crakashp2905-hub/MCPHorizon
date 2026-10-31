//! Monotone ground-rule closure, deterministic, with budgets. Mirrors horizon/core/closure.py.
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_RULES: usize = 1000;
pub const MAX_PREMISES: usize = 4;
pub const MAX_ATOMS: usize = 10000;

pub fn atom_ok(a: &str) -> bool {
    let cs: Vec<char> = a.chars().collect();
    let Some(open) = cs.iter().position(|c| *c == '(') else { return false };
    if cs.last() != Some(&')') || open == 0 { return false; }
    let name = &cs[..open];
    if !name[0].is_ascii_lowercase() || !name.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_') { return false; }
    let arg = &cs[open + 1..cs.len() - 1];
    arg.len() <= 128 && arg.iter().all(|c| c.is_ascii_alphanumeric() || "_.:/*?@-".contains(*c))
}
fn code_ok(c: &str) -> bool {
    let cs: Vec<char> = c.chars().collect();
    (2..=64).contains(&cs.len()) && cs[0].is_ascii_uppercase() && cs.iter().all(|x| x.is_ascii_uppercase() || x.is_ascii_digit() || *x == '_')
}

struct Rule { id: String, premises: Vec<String>, head: String, code: String }

fn parse_rules(rules: &[Value]) -> Result<Vec<Rule>, String> {
    if rules.len() > MAX_RULES { return Err("too many rules".into()); }
    let mut seen = BTreeSet::new(); let mut out = Vec::new();
    for r in rules {
        let o = r.as_object().ok_or("rule not object")?;
        let keys: BTreeSet<&str> = o.keys().map(|k| k.as_str()).collect();
        if keys != ["code", "head", "id", "premises"].into_iter().collect() { return Err("bad rule shape".into()); }
        let id = o["id"].as_str().ok_or("id")?.to_string();
        if !seen.insert(id.clone()) { return Err("duplicate id".into()); }
        let prem: Vec<&str> = o["premises"].as_array().ok_or("premises")?.iter().map(|p| p.as_str().ok_or("premise")).collect::<Result<_, _>>()?;
        if prem.is_empty() || prem.len() > MAX_PREMISES { return Err("arity".into()); }
        let head = o["head"].as_str().ok_or("head")?;
        if !prem.iter().all(|a| atom_ok(a)) || !atom_ok(head) { return Err("malformed atom".into()); }
        let code = o["code"].as_str().ok_or("code")?;
        if !code_ok(code) { return Err("bad code".into()); }
        let set: BTreeSet<String> = prem.iter().map(|s| s.to_string()).collect();
        out.push(Rule { id, premises: set.into_iter().collect(), head: head.into(), code: code.into() });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

pub fn closure(atoms: &[Value], rules: &[Value]) -> Result<Value, String> {
    let rs = parse_rules(rules)?;
    let mut x: BTreeSet<String> = BTreeSet::new();
    for a in atoms { let s = a.as_str().ok_or("atom")?; if !atom_ok(s) { return Err("malformed atom".into()); } x.insert(s.to_string()); }
    if x.len() > MAX_ATOMS { return Err("too many atoms".into()); }
    let mut wit: BTreeMap<String, Value> = BTreeMap::new();
    let mut changed = true;
    while changed {
        changed = false;
        for r in &rs {
            if !x.contains(&r.head) && r.premises.iter().all(|p| x.contains(p)) {
                x.insert(r.head.clone());
                wit.insert(r.head.clone(), json!({"rule": r.id, "premises": r.premises, "code": r.code}));
                changed = true;
                if x.len() > MAX_ATOMS { return Err("closure exceeded atom budget".into()); }
            }
        }
    }
    let mut w = Map::new(); for (k, v) in wit { w.insert(k, v); }
    Ok(json!({"atoms": x.into_iter().collect::<Vec<_>>(), "witnesses": Value::Object(w)}))
}
