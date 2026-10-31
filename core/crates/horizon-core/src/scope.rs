//! Bounded glob matching and sound-but-incomplete subsumption. See horizon/core/scope.py for the semantics.
use serde_json::Value;

pub const MAX_GLOB_LEN: usize = 256;
pub const MAX_WILDCARDS: usize = 8;
pub const MAX_TEXT: usize = 4096;

#[derive(Debug, PartialEq)]
pub struct ScopeError(pub String);
fn err<T>(m: &str) -> Result<T, ScopeError> { Err(ScopeError(m.to_string())) }

#[derive(Clone, Debug, PartialEq)]
enum Tok { Lit(char), One, Star, Star2 }

fn tokens(g: &str) -> Result<Vec<Tok>, ScopeError> {
    let cs: Vec<char> = g.chars().collect();
    if cs.len() > MAX_GLOB_LEN { return err("glob too long"); }
    if cs.iter().any(|c| "[]{}()\\|^$+\0".contains(*c)) { return err("unsupported glob syntax"); }
    let (mut out, mut i) = (Vec::new(), 0);
    while i < cs.len() {
        if cs[i] == '*' && i + 1 < cs.len() && cs[i + 1] == '*' {
            if i + 2 < cs.len() && cs[i + 2] == '*' { return err("*** not allowed"); }
            out.push(Tok::Star2); i += 2;
        } else {
            out.push(match cs[i] { '*' => Tok::Star, '?' => Tok::One, c => Tok::Lit(c) }); i += 1;
        }
    }
    if out.iter().filter(|t| !matches!(t, Tok::Lit(_))).count() > MAX_WILDCARDS { return err("too many wildcards"); }
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct Scope { pub kind: String, pub value: Option<String> }

impl Scope {
    pub fn from_json(v: &Value) -> Result<Scope, ScopeError> {
        let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string();
        let value = match v.get("value") { Some(Value::String(s)) => Some(s.clone()), Some(Value::Null) | None => None, _ => return err("bad value") };
        Ok(Scope { kind, value })
    }
    pub fn validate(&self) -> Result<(), ScopeError> {
        match self.kind.as_str() {
            "any" => if matches!(self.value.as_deref(), None | Some("")) { Ok(()) } else { err("any takes no value") },
            "literal" | "glob" | "tenant" => {
                let v = match self.value.as_deref() { Some(v) if !v.is_empty() => v, _ => return err("needs a value") };
                if self.kind == "glob" { tokens(v)?; }
                if self.kind == "tenant" && (v.contains('/') || !v.is_ascii()) { return err("bad tenant"); }
                Ok(())
            }
            _ => err("bad scope kind"),
        }
    }
    fn v(&self) -> &str { self.value.as_deref().unwrap_or("") }
}

pub fn glob_match(pattern: &str, text: &str) -> Result<bool, ScopeError> {
    let t: Vec<char> = text.chars().collect();
    if t.len() > MAX_TEXT { return err("text too long"); }
    let toks = tokens(pattern)?;
    let n = t.len();
    let mut nxt_slash = vec![n; n + 1];
    for i in (0..n).rev() { nxt_slash[i] = if t[i] == '/' { i } else { nxt_slash[i + 1] }; }
    let mut cur: Vec<bool> = vec![false; n + 1]; cur[0] = true;
    for tok in &toks {
        let mut nxt = vec![false; n + 1];
        match tok {
            Tok::Star2 => { if let Some(m) = cur.iter().position(|b| *b) { for x in m..=n { nxt[x] = true; } } }
            Tok::Star => {
                let mut covered: isize = -1;
                for p in 0..=n { if cur[p] {
                    let end = nxt_slash[p] as isize;
                    if end > covered { for x in (p as isize).max(covered + 1)..=end { nxt[x as usize] = true; } covered = end; }
                } }
            }
            Tok::One => { for p in 0..n { if cur[p] && t[p] != '/' { nxt[p + 1] = true; } } }
            Tok::Lit(c) => { for p in 0..n { if cur[p] && t[p] == *c { nxt[p + 1] = true; } } }
        }
        if !nxt.iter().any(|b| *b) { return Ok(false); }
        cur = nxt;
    }
    Ok(cur[n])
}

pub fn matches(s: &Scope, value: &str) -> Result<bool, ScopeError> {
    s.validate()?;
    Ok(match s.kind.as_str() {
        "any" => true,
        "literal" => s.v() == value,
        "tenant" => value == s.v() || value.starts_with(&format!("{}/", s.v())),
        _ => glob_match(s.v(), value)?,
    })
}

fn fixed_prefix_only(p: &str) -> bool { !p.contains('*') && !p.contains('?') }

pub fn subsumes(a: &Scope, b: &Scope) -> Result<bool, ScopeError> {
    a.validate()?; b.validate()?;
    let (ka, kb, va, vb) = (a.kind.as_str(), b.kind.as_str(), a.v(), b.v());
    if ka == "any" { return Ok(true); }
    if kb == "any" { return Ok(false); }
    Ok(match ka {
        "tenant" => match kb {
            "tenant" => va == vb,
            "literal" => vb == va || vb.starts_with(&format!("{}/", va)),
            _ => vb.starts_with(&format!("{}/", va)),
        },
        "literal" => kb == "literal" && va == vb,
        _ => {
            if kb == "literal" { return glob_match(va, vb); }
            if kb == "tenant" { return Ok(false); }
            if va == vb { return Ok(true); }
            if let Some(p) = va.strip_suffix("**") {
                if fixed_prefix_only(p) { return Ok(vb.starts_with(p)); }
            }
            if let Some(p) = va.strip_suffix('*') {
                if !va.ends_with("**") && fixed_prefix_only(p) {
                    if !vb.starts_with(p) { return Ok(false); }
                    let rest = &vb[p.len()..];
                    return Ok(!rest.contains('/') && !rest.contains("**"));
                }
            }
            false
        }
    })
}
