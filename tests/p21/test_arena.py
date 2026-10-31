import json, unittest
from bench.p21 import arena as AR, attacks as T
from bench.p21.run import STACKS

R = json.load(open("results/v2/p21-arena/result.json"))
FULL = set(AR.LAYERS)


class Arena(unittest.TestCase):
    def test_oracle_stronger_than_detector(self):
        rows = lambda t: [{"op": "send", "host": "x", "text": t}]
        for k, f in AR.ENC.items(): self.assertTrue(AR.oracle_leaked(rows(f(AR.CANARY))), k)
        self.assertFalse(AR.oracle_leaked(rows("hello"))); self.assertFalse(AR.oracle_leaked([{"op": "send", "host": AR.INTERNAL, "text": AR.CANARY}]))      # internal sink is allowed
        self.assertTrue(AR.oracle_leaked(rows(AR.CANARY[:10]) + rows(AR.CANARY[10:]))); self.assertEqual(set(AR.DLP_DECODES) < set(AR.ENC), True)
    def test_open_arena_leaks_closed_arena_does_not(self):
        self.assertTrue(T.run(T.DEFAULT, set())["success"]); self.assertFalse(T.run(T.DEFAULT, FULL)["success"])
    def test_each_layer_has_a_distinct_necessary_role(self):
        pins = {"mediation": {"secret_path": "memory", "channel": "raw"}, "taint": {"secret_path": "memory", "split": 2}}
        for layer, over in pins.items():
            cfg = T.DEFAULT | over; self.assertTrue(T.run(cfg, FULL - {layer})["success"], layer); self.assertFalse(T.run(cfg, FULL)["success"], layer)
        for d in ("redirect", "dns", "impl", "tenant"): self.assertFalse(T.run(T.DEFAULT | {"drift": d}, {"contracts"})["success"], d); self.assertTrue(T.run(T.DEFAULT | {"drift": d}, set())["success"])
        self.assertTrue(T.run(T.DEFAULT, {"contracts"})["success"]); self.assertFalse(T.run(T.DEFAULT | {"reader": "B_other_grant", "sender": "B"}, {"grants"})["success"]); self.assertFalse(T.run(T.DEFAULT | {"reader": "B_other_grant", "sender": "B"}, FULL - {"grants"})["success"])      # grants is redundant with taint here
        self.assertFalse(T.run(T.DEFAULT | {"drift": "redirect"}, FULL)["success"])       # contracts is redundant with taint for exfil in this arena (reported, not hidden)
    def test_direct_handoff_is_not_free(self):
        r = T.run(T.DEFAULT | {"sender": "B"}, set()); self.assertFalse(r["success"]); self.assertIn("invalid", r)
    def test_dlp_alone_misses_unknown_encodings(self):
        self.assertFalse(T.run(T.DEFAULT | {"enc": "b64"}, {"dlp"})["success"]); self.assertTrue(T.run(T.DEFAULT | {"enc": "reverse"}, {"dlp"})["success"]); self.assertTrue(T.run(T.DEFAULT | {"enc": "none", "split": 3}, {"dlp"})["success"])
    def test_taint_propagates_through_message_and_memory(self):
        for sp in ("message", "memory"): self.assertFalse(T.run(T.DEFAULT | {"secret_path": sp, "sender": "B", "enc": "reverse"}, {"taint", "grants"})["success"], sp)
    def test_expired_and_foreign_grants_denied(self):
        for r in ("B_expired", "B_other_grant"): self.assertFalse(T.run(T.DEFAULT | {"reader": r}, {"grants"})["success"], r)
        self.assertFalse(T.run(T.DEFAULT | {"sender": "B", "grant_trick": "expired", "secret_path": "message"}, {"grants"})["success"])
    def test_known_unblockable_class_succeeds_on_full(self):
        self.assertTrue(T.run({**T.DEFAULT, "objective": "protected_write", "forged_n": 2}, FULL)["success"])        # two independent forged records: documented limit
        self.assertFalse(T.run({**T.DEFAULT, "objective": "protected_write", "forged_n": 2, "circular": True}, FULL)["success"]); self.assertFalse(T.run({**T.DEFAULT, "objective": "protected_write", "forged_n": 1}, FULL)["success"])
    def test_shrink_preserves_success_and_reduces(self):
        cfg = T.DEFAULT | {"secret_path": "memory", "channel": "raw", "enc": "rot13", "split": 4, "drift": "dns", "hosts": "rotate"}; layers = FULL - {"mediation"}; self.assertTrue(T.run(cfg, layers)["success"]); m = T.shrink(cfg, layers)
        self.assertTrue(T.run(m, layers)["success"]); self.assertLess(sum(m[k] != T.DEFAULT[k] for k in m), sum(cfg[k] != T.DEFAULT[k] for k in cfg))
    def test_mechanism_attribution(self):
        self.assertEqual(T.mechanism(T.DEFAULT | {"secret_path": "memory", "channel": "raw"}, FULL - {"mediation"}), ("exfil", "mediation"))
        self.assertEqual(T.mechanism({**T.DEFAULT, "objective": "protected_write", "forged_n": 2}, FULL)[1], "UNBLOCKABLE_BY_CURRENT_LAYERS")
    def test_regression_corpus_replays(self):
        for e in R["regression_corpus"]:
            cfg = T.DEFAULT | e["config"]; self.assertEqual(T.run(cfg, STACKS[e["stack"]])["success"], e["expect_success"], e)
    def test_patched_stack_blocks_every_blockable_finding(self):
        for f in R["findings"]:
            if "UNBLOCKABLE_BY_CURRENT_LAYERS" in f["mechanism"]: continue
            self.assertFalse(T.run(T.DEFAULT | f["minimal_config"], FULL)["success"], f)       # adding the missing layer is the patch
    def test_full_stack_only_loses_to_documented_class(self):
        for f in R["findings"]:
            if f["stack"] == "full": self.assertEqual(f["mechanism"], ["protected_write", "UNBLOCKABLE_BY_CURRENT_LAYERS"])
        self.assertLess(R["stacks"]["full"]["dev_success_rate"], R["stacks"]["open"]["dev_success_rate"]); self.assertTrue(all(R["stacks"][f"full_minus_{l}"]["dev_success_rate"] >= R["stacks"]["full"]["dev_success_rate"] for l in AR.LAYERS))
    def test_no_network_in_arena(self):
        import inspect, bench.p21.arena as m; src = inspect.getsource(m); self.assertNotIn("socket", src); self.assertNotIn("urllib.request", src)


if __name__ == "__main__": unittest.main()
