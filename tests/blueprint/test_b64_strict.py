import base64, os, sys, unittest
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); sys.path.insert(0, R)
from horizon.authz import effect as E
from horizon.authz.keys import Signer
from horizon.ops import audience as A
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
def variants(sig_b64):
    """All 16 spellings of a 64-byte signature's last char that decode to the same bytes."""
    last = sig_b64[-1]; idx = ALPH.index(last); base = idx & ~0xF
    return [sig_b64[:-1] + ALPH[base + i] for i in range(16)]
EFF = dict(v=1, iss="iss", sub="agent-a", tenant="t1", effect="write", target={"kind": "file", "canonical_id": "/x"}, args_digest="sha256:" + "a" * 64, contract_version="c1", policy_version="p1", aud="gw", iat=1, exp=2, nonce="n" * 16, decision_id="d")
class Strict(unittest.TestCase):
    def test_roundtrip_canonical_all_lengths(self):
        for n in range(0, 80): b = os.urandom(n); self.assertEqual(E.b64d(E.b64e(b)), b); self.assertEqual(A._unb64(A._b64(b)), b)
    def test_exactly_one_of_sixteen_signature_spellings_accepted(self):
        sig = os.urandom(64); s = E.b64e(sig); vs = variants(s); self.assertEqual(len(set(vs)), 16)
        ok = [v for v in vs if self._ok(E.b64d, v)]; self.assertEqual(ok, [s]); self.assertEqual([v for v in vs if self._ok(A._unb64, v)], [s])
        for v in vs: self.assertEqual(base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)), sig)      # proves they ARE the same bytes: the old decoder accepted all 16
    def _ok(self, f, v):
        try: f(v); return True
        except (E.EffectError, A.AuthError): return False
    def test_malformed_lengths_and_alphabet_raise_domain_errors_not_binascii(self):
        for bad in ("A", "AAAAA", "AA==", "a b", "AA+/", "é", ""[:0] + "A" * 5):
            for f, exc in ((E.b64d, E.EffectError), (A._unb64, A.AuthError)):
                if bad == "": continue
                with self.assertRaises(exc): f(bad)
        for f, exc in ((E.b64d, E.EffectError), (A._unb64, A.AuthError)):
            for nonstr in (None, 5, b"AA"):
                with self.assertRaises(exc): f(nonstr)
    def test_padding_characters_rejected(self):
        with self.assertRaises(E.EffectError): E.b64d("QQ==")
        self.assertEqual(E.b64d("QQ"), b"A")
    def test_noncanonical_signature_rejected_end_to_end(self):
        sg = Signer.generate("k1", "iss"); tok = E.sign(sg._p, "k1", EFF); hh, pp, ss = tok.split("."); E.parse(tok)
        bad = [v for v in variants(ss) if v != ss]; self.assertEqual(len(bad), 15)
        for v in bad:
            with self.assertRaises(E.EffectError): E.parse(".".join([hh, pp, v]))
    def test_noncanonical_header_or_body_segment_rejected(self):
        sg = Signer.generate("k1", "iss"); tok = E.sign(sg._p, "k1", EFF); hh, pp, ss = tok.split(".")
        for seg_i in (0, 1):
            seg = [hh, pp][seg_i]
            if len(seg) % 4 == 1: continue
            alt = [v for v in variants(seg) if v != seg and len(seg) % 4 in (2, 3)]
            for v in alt:
                parts = [hh, pp, ss]; parts[seg_i] = v
                with self.assertRaises(E.EffectError): E.parse(".".join(parts))
if __name__ == "__main__": unittest.main()
