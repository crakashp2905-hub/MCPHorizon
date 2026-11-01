#!/usr/bin/env python3
"""P38-01/02: validates research/incident-casebook/index.yaml and generates docs/evidence/p38/{CASEBOOK_VERIFICATION,DISPUTED_CLAIMS}.md. `--check` fails if committed files differ or the index breaks a rule:
every case has provenance + access dates; a claim may be CONFIRMED only if a source for it was actually fetched; no intent inference."""
import os, re, sys, yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDX = os.path.join(ROOT, "research", "incident-casebook", "index.yaml"); OUT = os.path.join(ROOT, "docs", "evidence", "p38")
OK_STATUS = {"CONFIRMED", "CONFIRMED_VIA_SECONDARY", "ARITHMETIC_CONFIRMED", "CONFIRMED_AS_ABSENCE", "CONSISTENT", "NOT_VERIFIED", "NOT_VERIFIED_ON_THIS_PAGE"}
INTENT = re.compile(r"(?i)\b(deliberately|intentionally)\s+(insert|inject|plant|backdoor)|developer complicity|state[- ]sponsored sabotage")
def load(): return yaml.safe_load(open(IDX))
def problems(d):
    p = []
    for c in d["cases"]:
        if not c.get("provenance") or not c.get("publication_date"): p.append(f"{c['id']}: missing provenance/publication_date")
        acc = c.get("independent_accounts", [])
        if not c.get("primary_fetched") and not any(a.get("fetched") for a in acc): p.append(f"{c['id']}: no source was actually fetched")
        for a in acc:
            if a.get("fetched") and not a.get("accessed"): p.append(f"{c['id']}: fetched source without access date")
        for v in c["verified_claims"]:
            if v["status"] not in OK_STATUS: p.append(f"{c['id']}: bad status {v['status']}")
            if v["status"] == "CONFIRMED" and not (c.get("primary_fetched") or any(a.get("fetched") for a in acc)): p.append(f"{c['id']}: CONFIRMED without fetched source")
            if INTENT.search(v["claim"] + " " + v["detail"]): p.append(f"{c['id']}: intent inference in claim text")
    return p
def build(d):
    V = ["# P38-01 casebook source verification", "", f"_Generated from `research/incident-casebook/index.yaml` (accessed {d['accessed']}). {d['access_note']}_", ""]
    D = ["# P38-02 disputed or potentially misleading headline interpretations", "", "Corrections found while checking the spec §45 casebook against the sources actually read. Items marked UNVERIFIED need a source that was not readable in this session.", ""]
    for c in d["cases"]:
        V += [f"## {c['id']}", f"* characterization: {c['characterization']}; provenance: {c['provenance']}", f"* published: {c['publication_date']}; incident: {c['incident_date'] or 'not stated'}", f"* primary: {c['primary_url'] or 'not located'} — fetched: {c['primary_fetched']} ({c['primary_fetch_note']})"]
        for a in c.get("independent_accounts", []): V.append(f"* other source: {a['url']} — {a['kind']}; fetched: {a['fetched']}; accessed: {a.get('accessed')}")
        V += ["", "| Claim | Status | Detail |", "|---|---|---|"] + [f"| {v['claim']} | {v['status']} | {v['detail']} |" for v in c["verified_claims"]] + ["", "Limits: " + "; ".join(c["limits"]), ""]
        if c["corrections"]: D += [f"## {c['id']}"] + [f"* {x}" for x in c["corrections"]] + [""]
    n = [v["status"] for c in d["cases"] for v in c["verified_claims"]]; V += [f"**Totals:** {len(n)} claims; " + ", ".join(f"{k} {n.count(k)}" for k in sorted(set(n))) + "."]
    return "\n".join(V) + "\n", "\n".join(D) + "\n"
if __name__ == "__main__":
    d = load(); pr = problems(d); [print("PROBLEM", x) for x in pr]; v, dd = build(d)
    if "--check" in sys.argv:
        ok = not pr and open(os.path.join(OUT, "CASEBOOK_VERIFICATION.md")).read() == v and open(os.path.join(OUT, "DISPUTED_CLAIMS.md")).read() == dd; print("p38 casebook:", "OK" if ok else "FAIL"); sys.exit(0 if ok else 1)
    os.makedirs(OUT, exist_ok=True); open(os.path.join(OUT, "CASEBOOK_VERIFICATION.md"), "w").write(v); open(os.path.join(OUT, "DISPUTED_CLAIMS.md"), "w").write(dd); print("wrote; problems:", len(pr)); sys.exit(1 if pr else 0)
