import json, os, subprocess, sys, unittest
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
def run(s): return subprocess.run([sys.executable, "-B", os.path.join(R, "scripts", s)], cwd=R, capture_output=True, text=True, timeout=300)
class T(unittest.TestCase):
    def test_route_trace_current(self):
        r = run("route_trace.py"); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
    def test_module_inventory_current(self):
        r = run("module_inventory.py"); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
    def test_inventory_has_47_groups_and_unmapped_are_honest(self):
        g = json.load(open(os.path.join(R, "docs/evidence/integration/MODULE_INVENTORY.json"))); self.assertEqual(g["count"], 47)
        for m in g["modules"]: self.assertEqual(m["status"], "CANDIDATE" if m["present"] else "UNMAPPED")
        self.assertEqual({m["id"] for m in g["modules"] if not m["present"]} >= {"F05", "F06", "F07"}, True)
if __name__ == "__main__": unittest.main()
