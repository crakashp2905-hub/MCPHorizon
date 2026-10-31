//! Confidentiality / trust lattices.
pub const CONF: [&str; 4] = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"];
pub const TRUST: [&str; 3] = ["UNTRUSTED", "UNVERIFIED", "TRUSTED"];
pub fn conf_rank(s: &str) -> Option<usize> { CONF.iter().position(|x| *x == s) }
pub fn trust_rank(s: &str) -> Option<usize> { TRUST.iter().position(|x| *x == s) }
pub fn join_conf(xs: &[usize]) -> &'static str { CONF[xs.iter().copied().max().unwrap_or(0)] }
pub fn meet_trust(xs: &[usize]) -> &'static str { TRUST[xs.iter().copied().min().unwrap_or(2)] }
