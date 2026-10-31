//! Rust core mirroring `horizon/core/*.py` (the Python reference/oracle). Differential tests must agree exactly.
pub mod closure;
pub mod decide;
pub mod labels;
pub mod scope;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sc(k: &str, v: &str) -> scope::Scope { scope::Scope { kind: k.into(), value: Some(v.into()) } }

    #[test]
    fn glob_semantics_and_rejections() {
        assert_eq!(scope::glob_match("/a/*", "/a/b"), Ok(true));
        assert_eq!(scope::glob_match("/a/*", "/a/b/c"), Ok(false));
        assert_eq!(scope::glob_match("/a/**", "/a/b/c"), Ok(true));
        for bad in ["(a+)+$", "[a-z]", "a|b", "***"] { assert!(scope::glob_match(bad, "a").is_err(), "{bad}"); }
        assert!(scope::glob_match("*a*a*a*a*a*a*a*b", &"a".repeat(4000)).is_ok()); // linear, no blow-up
    }

    #[test]
    fn subsumption_sound_and_incomplete() {
        assert_eq!(scope::subsumes(&sc("glob", "/a/**"), &sc("glob", "/a/b/*")), Ok(true));
        assert_eq!(scope::subsumes(&sc("tenant", "t1"), &sc("literal", "t10/x")), Ok(false));
        assert_eq!(scope::subsumes(&sc("glob", "/a/*/*"), &sc("glob", "/a/*/c")), Ok(false)); // documented incompleteness
    }

    #[test]
    fn closure_and_decide() {
        let rules = vec![json!({"id": "r1", "premises": ["cap(a)", "cap(b)"], "head": "cap(c)", "code": "HEAD_C"})];
        let out = closure::closure(&[json!("cap(a)"), json!("cap(b)")], &rules).unwrap();
        assert!(out["atoms"].as_array().unwrap().contains(&json!("cap(c)")));
        assert!(closure::closure(&[json!("not an atom")], &rules).is_err());
        let policy = json!({"rules": [{"id": "d", "when": {"effect": "send"}, "decision": "DENY"}, {"id": "a", "when": {"effect": "send"}, "decision": "ALLOW"}],
                            "defaults": {"protected_effect": "DENY", "inspection_only": "QUARANTINE"}});
        let ctx = json!({"identity_valid": true, "interceptable": true, "mapping_complete": true, "protected_effect": true, "effect": "send",
                         "input_label": "PUBLIC", "lineage_complete": true, "authorized_flow": true, "approval": {"valid": true}});
        assert_eq!(decide::decide(&policy, &ctx)["verdict"], "DENY"); // hard deny beats allow + approval
    }
}
