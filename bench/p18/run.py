"""P18-14/15: delayed-harm scenarios across sessions; provenance memory vs no-provenance vs session-only taint vs offline reconstruction. Write-once."""
import json, random, subprocess, sys, time
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from horizon.memory.store import Label, Store

SEED, N = 18, 200
U = Label("UNTRUSTED", "PUBLIC", "T1", "u"); SEC = Label("TRUSTED", "SECRET", "T1", "u", frozenset({"vault"})); OK = Label("TRUSTED", "PUBLIC", "T1", "u")


def scenarios():
    r = random.Random(SEED); return [{"i": i, "kind": r.choice(["poison_instruction", "delayed_leak", "laundered_summary", "benign_recall", "benign_recall", "benign_summary"]), "hops": r.randint(1, 3)} for i in range(N)]


def run(system, sc):
    """Returns (harm_occurred, benign_blocked). A 'harm' = a later-session action acts on poisoned instruction or sends SECRET-derived memory to a sink."""
    s = Store(); k = sc["kind"]; src_label = {"poison_instruction": U, "laundered_summary": U, "delayed_leak": SEC}.get(k, OK)
    cur = s.put("T1", "u", f"payload {sc['i']} word", src_label, session="s1")
    for h in range(sc["hops"]): cur = s.summarize("T1", "u", [cur], f"summary{h} payload {sc['i']} word", session=f"s{h + 2}")
    if system == "no_provenance": allow_instr = allow_sink = True                                   # labels dropped on store
    elif system == "session_only_taint": allow_instr = allow_sink = True                             # taint lived only in the originating session; later sessions see nothing
    else: a = s.authority_of(cur); allow_instr, allow_sink = a["may_instruct"], a["may_flow_to_sink"]
    harm = (k in ("poison_instruction", "laundered_summary") and allow_instr) or (k == "delayed_leak" and allow_sink)
    blocked = k.startswith("benign") and not (allow_instr and allow_sink)
    return harm, blocked


def main():
    out = REPO / "results/v2/p18-memory"
    if (out / "result.json").exists(): raise SystemExit("write-once")
    sc = scenarios(); res = {}
    for sysn, key in (("provenance_memory", "provenance_memory"), ("no_provenance", "no_provenance"), ("session_only_taint", "session_only_taint")):
        t = time.perf_counter(); rows = [run(key, x) for x in sc]; dt = time.perf_counter() - t; H = [r for r, x in zip(rows, sc) if not x["kind"].startswith("benign")]; B = [r for r, x in zip(rows, sc) if x["kind"].startswith("benign")]
        res[sysn] = {"harm_scenarios": len(H), "missed_delayed_harms": sum(h for h, _ in H), "benign_scenarios": len(B), "benign_recall_blocked": sum(b for _, b in B), "seconds": round(dt, 4)}
    s = Store(); i = s.put("T1", "u", "x" * 100, OK); res["storage_overhead"] = {"content_bytes": 100, "label_and_meta_fields_per_record": 8, "note": "in-process reference store; not a storage-engine measurement"}
    res["offline_reconstruction"] = {"note": "detects the harm only AFTER the action via Store.reconstruct; prevents nothing, so every harm scenario counts as 'detected late'", "detected_late": sum(1 for x in sc if not x["kind"].startswith("benign") and x["kind"] != "none")}
    out.mkdir(parents=True, exist_ok=True); (out / "result.json").write_text(json.dumps(res, indent=1))
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    (out / "manifest.json").write_text(json.dumps({"experiment_id": "p18-memory", "git_sha": sha, "command": "python3 bench/p18/run.py", "seed": SEED, "n": N, "status": "candidate; scripted scenarios, baselines are definitional models"}, indent=1)); print(json.dumps(res, indent=1))


if __name__ == "__main__": main()
