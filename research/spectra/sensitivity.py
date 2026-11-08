"""Spectra probe-selection SENSITIVITY analysis (blueprint A6, honest version). CANDIDATE.
Why not 'Spectra on real fixtures': no vendored dataset labels which sink a real tool touches at run time, so ground truth for hidden effects does not exist. MCPTox labels poisoned DESCRIPTIONS, and its def_tool names are random decoy words.
What IS real and used: the 45 server names and per-server case counts in MCPTox/pure_tool.json (485 cases). SERVER_KIND maps each server to a probe kind by MY OWN keyword judgement (disclosed, unreviewed); the resulting kind mix is one condition among several.
Hidden effects are still simulated. The analysis asks one question: does the previously measured lack of advantage for active probe selection survive other kind mixes, larger systems, and a hidden-effect location biased toward network tools (favourable to the expert-rule baseline)?"""
from __future__ import annotations
import collections, json, os, sys
from . import compare as C
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SERVER_KIND = {**{s: "net" for s in ("Email", "Financial Dataset", "Github", "OP.GG", "mcp-simple-arxiv", "AlphaVantage", "Apify", "Codacy", "Slack", "AdFin", "DumplingAI", "HyperBrowser", "BraveSearch", "BaiduMap", "AmapMap", "EverArt", "Gitlab",
                                       "DoDo Payments", "AgentQL", "Google Maps", "Gyazo", "Claude Post", "wechat", "Tavily", "KeywordsPeopleUse", "GoogleDrive", "AWSKnowledgeBase", "Flomo", "QuickChart", "Fetch", "12306-mcp", "Sentry", "Puppeteer")},
               **{s: "file" for s in ("FileSystem", "Git", "Memory", "SQLite", "Prisma", "ClickHouse", "Redis")},
               **{s: "proc" for s in ("Commander", "E2B")}, **{s: "local" for s in ("Sequential Thinking", "gNucleus Text to CAD", "Everything")}}
def mcptox_mix(path=None):
    d = json.load(open(path or os.path.join(ROOT, "MCPTox", "pure_tool.json"))); cnt = collections.Counter(v["server_name"] for e in d for v in e.values())
    unmapped = sorted(set(cnt) - set(SERVER_KIND))
    if unmapped: raise ValueError("unmapped servers: %s" % unmapped)
    w = collections.Counter()
    for s, n in cnt.items(): w[SERVER_KIND[s]] += n
    return {k: w.get(k, 0) / sum(w.values()) for k in C.KINDS}
def conditions(mix):
    net_bias = {"net": 3.0, "proc": 3.0}
    return {"uniform_kinds/uniform_target": dict(kind_weights=None, target_bias=None), "mcptox_mix/uniform_target": dict(kind_weights=mix, target_bias=None), "uniform_kinds/net_proc_biased_target": dict(kind_weights=None, target_bias=net_bias),
            "mcptox_mix/net_proc_biased_target": dict(kind_weights=mix, target_bias=net_bias), "mcptox_mix/16_probes": dict(kind_weights=mix, target_bias=None, n_probes=16), "mcptox_mix/16_probes_biased": dict(kind_weights=mix, target_bias=net_bias, n_probes=16)}
def run(n_worlds=300, seed=2026, path=None):
    mix = mcptox_mix(path); out = {"kind_mix_from_mcptox_servers": {k: round(v, 4) for k, v in mix.items()}, "n_worlds_each": n_worlds, "seed": seed, "conditions": {}}
    for name, kw in conditions(mix).items():
        r = C.experiment(n_worlds, seed, budgets=(2, 4, 8, 16) if kw.get("n_probes") == 16 else (2, 4, 8), **kw)
        out["conditions"][name] = {"discoverable_worlds": r["worlds_with_discoverable_hidden_effect"], "mean_probes_to_discovery": {k: v["mean_probes_to_discovery"] for k, v in r["strategies"].items()},
                                   "active_saves_vs_95ci": r["paired_bootstrap_95ci_mean_probes_saved_by_active_vs"], "ci_excludes_zero_in_favour_of_active": sorted(k for k, (lo, hi) in r["paired_bootstrap_95ci_mean_probes_saved_by_active_vs"].items() if lo > 0)}
    out["note"] = "simulated hidden effects; kind mix derived from real MCPTox server names via a self-authored keyword table; NOT independent, NOT held-out, NOT real tool behaviour"
    return out
if __name__ == "__main__":
    r = run(); json.dump(r, open(sys.argv[1] if len(sys.argv) > 1 else "/dev/stdout", "w"), indent=1, sort_keys=True)
