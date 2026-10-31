// Schema-level verdict per fixture using the `jsonschema` crate (independent of Python and Ajv).
use std::{collections::BTreeMap, fs, path::{Path, PathBuf}};
fn walk(d: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(d).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() { walk(&p, out) } else { out.push(p) }
    }
}
fn main() {
    let root = PathBuf::from(std::env::args().nth(1).expect("repo root"));
    let mut validators = BTreeMap::new();
    for e in fs::read_dir(root.join("schemas")).unwrap() {
        let p = e.unwrap().path();
        let kind = p.file_name().unwrap().to_string_lossy().replace(".schema.json", "");
        let schema: serde_json::Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        validators.insert(kind, jsonschema::validator_for(&schema).expect("schema compiles"));
    }
    let base = root.join("tests/fixtures");
    let mut files = vec![]; walk(&base, &mut files); files.sort();
    let mut out = BTreeMap::new();
    for f in files {
        let kind = f.parent().unwrap().file_name().unwrap().to_string_lossy().to_string();
        let raw = fs::read_to_string(&f).unwrap();
        // serde_json rejects what Python/JS accept only in documented ways; parse failure counts as "invalid".
        let ok = match serde_json::from_str::<serde_json::Value>(&raw) { Ok(doc) => validators[&kind].is_valid(&doc), Err(_) => false };
        out.insert(f.strip_prefix(&base).unwrap().to_string_lossy().replace('\\', "/"), ok);
    }
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
