//! Reads differential cases (JSON), prints Rust results in the same shape as the Python oracle.
use horizon_core::{closure, decide, labels, scope};
use serde_json::{json, Value};

fn res<T: Into<Value>, E>(r: Result<T, E>) -> Value { match r { Ok(v) => v.into(), Err(_) => json!("ERR") } }

fn main() {
    let path = std::env::args().nth(1).expect("cases.json");
    let c: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut out = serde_json::Map::new();
    out.insert("scope_match".into(), c["scope_match"].as_array().unwrap().iter().map(|x| {
        res(scope::Scope::from_json(&x["scope"]).and_then(|s| scope::matches(&s, x["value"].as_str().unwrap())))
    }).collect::<Vec<_>>().into());
    out.insert("scope_subsumes".into(), c["scope_subsumes"].as_array().unwrap().iter().map(|x| {
        res(scope::Scope::from_json(&x["a"]).and_then(|a| scope::Scope::from_json(&x["b"]).and_then(|b| scope::subsumes(&a, &b))))
    }).collect::<Vec<_>>().into());
    out.insert("closure".into(), c["closure"].as_array().unwrap().iter().map(|x| {
        res(closure::closure(x["atoms"].as_array().unwrap(), x["rules"].as_array().unwrap()))
    }).collect::<Vec<_>>().into());
    out.insert("labels".into(), c["labels"].as_array().unwrap().iter().map(|x| {
        let cf: Vec<usize> = x["conf"].as_array().unwrap().iter().map(|s| labels::conf_rank(s.as_str().unwrap()).unwrap()).collect();
        let tr: Vec<usize> = x["trust"].as_array().unwrap().iter().map(|s| labels::trust_rank(s.as_str().unwrap()).unwrap()).collect();
        json!({"confidentiality": labels::join_conf(&cf), "trust": labels::meet_trust(&tr)})
    }).collect::<Vec<_>>().into());
    out.insert("decide".into(), c["decide"].as_array().unwrap().iter().map(|x| decide::decide(&x["policy"], &x["ctx"])).collect::<Vec<_>>().into());
    println!("{}", Value::Object(out));
}
