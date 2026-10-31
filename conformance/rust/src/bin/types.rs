// Every VALID fixture must deserialize into the generated Rust types and round-trip without data loss.
#[path = "../../../../types/rust/horizon_types.rs"]
mod horizon_types;
use horizon_types::*;
use std::{fs, path::PathBuf};

fn strip(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => serde_json::Value::Object(m.into_iter().filter(|(_, x)| !x.is_null()).map(|(k, x)| (k, strip(x))).collect()),
        serde_json::Value::Array(a) => serde_json::Value::Array(a.into_iter().map(strip).collect()),
        o => o,
    }
}
fn rt<T: serde::de::DeserializeOwned + serde::Serialize>(raw: &str) -> Result<bool, String> {
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let t: T = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
    // Option<T> cannot distinguish an explicit `null` from an absent optional key, so compare with nulls stripped.
    Ok(strip(serde_json::to_value(&t).map_err(|e| e.to_string())?) == strip(v))
}
fn main() {
    let root = PathBuf::from(std::env::args().nth(1).expect("repo root")).join("tests/fixtures/valid");
    let (mut n, mut bad) = (0, 0);
    for kind_dir in fs::read_dir(&root).unwrap() {
        let kd = kind_dir.unwrap().path();
        let kind = kd.file_name().unwrap().to_string_lossy().to_string();
        for f in fs::read_dir(&kd).unwrap() {
            let p = f.unwrap().path(); let raw = fs::read_to_string(&p).unwrap();
            let r = match kind.as_str() {
                "event" => rt::<Event>(&raw), "decision" => rt::<Decision>(&raw), "capability" => rt::<Capability>(&raw),
                "artifact" => rt::<Artifact>(&raw), "policy" => rt::<Policy>(&raw), "lineage_edge" => rt::<LineageEdge>(&raw),
                k => Err(format!("unknown kind {k}")),
            };
            n += 1;
            match r { Ok(true) => {}, other => { bad += 1; println!("FAIL {}: {:?}", p.display(), other); } }
        }
    }
    println!("rust types: {n} valid fixtures, {bad} failures");
    std::process::exit(if bad == 0 && n > 0 { 0 } else { 1 });
}
