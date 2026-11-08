import http.server, os, shutil, ssl, subprocess, tempfile, threading, time, unittest
from horizon.effects import netbroker as N, procbroker as Pr


def serve(handler_cls, tls=None):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    if tls:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(*tls); srv.socket = c.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start(); return srv


class H(http.server.BaseHTTPRequestHandler):
    hits = []
    def log_message(self, *a): pass
    def do_GET(self):
        H.hits.append((self.path, self.headers.get("Host")))
        if self.path == "/redir": self.send_response(302); self.send_header("Location", "/final"); self.end_headers(); return
        if self.path == "/big": body = b"x" * 5000
        elif self.path == "/slow": time.sleep(1.5); body = b"late"
        else: body = b"ok"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    do_POST = do_GET


def cert(dirname, san):
    k, c = os.path.join(dirname, f"{san}.key"), os.path.join(dirname, f"{san}.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", k, "-out", c, "-days", "2", "-subj", f"/CN={san}", "-addext", f"subjectAltName=DNS:{san}"], check=True, capture_output=True)
    return c, k


def code(f, *a, **k):
    try: f(*a, **k)
    except (N.NetBrokerError, Pr.ProcBrokerError) as e: return e.code
    return None


class Net(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.srv = serve(H); cls.port = cls.srv.server_address[1]
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()
    def setUp(self): H.hits.clear()
    def broker(self, answers=("127.0.0.1",), private=True, **kw):
        self.calls = []
        def res(h, p): self.calls.append(h); return list(answers)
        return N.NetBroker([N.Allow("http", "svc.test", self.port, allow_private=private)], resolver=res, **kw)
    def test_allowed_request_works_and_sends_original_host_header(self):
        st, body = self.broker().request("GET", f"http://svc.test:{self.port}/a"); self.assertEqual((st, body), (200, b"ok")); self.assertEqual(H.hits[0][1], f"svc.test:{self.port}")
    def test_dns_is_resolved_once_and_the_pinned_address_is_used(self):
        b = self.broker(); b.request("GET", f"http://svc.test:{self.port}/a"); self.assertEqual(self.calls, ["svc.test"])
    def test_private_answers_are_refused_unless_the_entry_allows_them(self):
        for a in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "100.64.0.1"):
            self.assertEqual(code(self.broker((a,), private=False).check, "GET", f"http://svc.test:{self.port}/"), "PRIVATE_ADDRESS", a)
    def test_a_mixed_answer_with_one_private_address_is_refused(self):
        self.assertEqual(code(self.broker(("93.184.216.34", "10.0.0.1"), private=False).check, "GET", f"http://svc.test:{self.port}/"), "PRIVATE_ADDRESS")
    def test_public_address_passes_the_policy_check(self):
        e, host, port, path, ip = self.broker(("93.184.216.34",), private=False).check("GET", f"http://svc.test:{self.port}/p?q=1"); self.assertEqual((ip, path), ("93.184.216.34", "/p?q=1"))
    def test_empty_or_garbage_dns_answers_fail_closed(self):
        self.assertEqual(code(self.broker(()).check, "GET", f"http://svc.test:{self.port}/"), "DNS_NO_ANSWER")
        self.assertEqual(code(self.broker(("not-an-ip",)).check, "GET", f"http://svc.test:{self.port}/"), "DNS_BAD_ADDRESS")
    def test_targets_outside_the_allowlist_are_refused(self):
        b = self.broker()
        for u in (f"http://other.test:{self.port}/", f"http://svc.test:{self.port + 1}/", f"https://svc.test:{self.port}/", f"http://127.0.0.1:{self.port}/", "ftp://svc.test/x"): self.assertIn(code(b.check, "GET", u), ("OUTSIDE_ALLOWED_TARGETS", "BAD_URL"), u)
    def test_an_allowed_ip_literal_is_not_sent_through_the_resolver(self):
        def boom(h, p): raise AssertionError("resolver must not be called for an IP literal")
        b = N.NetBroker([N.Allow("http", "127.0.0.1", self.port, allow_private=True)], resolver=boom); self.assertEqual(b.request("GET", f"http://127.0.0.1:{self.port}/")[0], 200)
        self.assertEqual(code(N.NetBroker([N.Allow("http", "127.0.0.1", self.port)], resolver=boom).check, "GET", f"http://127.0.0.1:{self.port}/"), "PRIVATE_ADDRESS")
    def test_host_is_normalised_and_case_insensitive(self): self.assertIsNone(code(self.broker().check, "GET", f"http://SVC.test:{self.port}/"))
    def test_userinfo_backslash_whitespace_and_nul_are_refused(self):
        b = self.broker()
        self.assertEqual(code(b.check, "GET", f"http://u:p@svc.test:{self.port}/"), "USERINFO_NOT_ALLOWED")
        for u in (f"http://svc.test:{self.port}/a b", f"http://svc.test:{self.port}\\@x/", f"http://svc.test:{self.port}/\x00", f"http://svc.test:{self.port}/a\r\nX: y"): self.assertEqual(code(b.check, "GET", u), "BAD_URL")
    def test_method_header_and_size_rules(self):
        b = self.broker(max_request=10); u = f"http://svc.test:{self.port}/"
        self.assertEqual(code(b.check, "TRACE", u), "BAD_METHOD"); self.assertEqual(code(b.check, "POST", u, {}, b"x" * 11), "REQUEST_TOO_LARGE")
        for h in ({"Host": "evil"}, {"Content-Length": "1"}, {"X\r\nY": "1"}, {"X": "a\nb"}, {"Proxy-Authorization": "x"}): self.assertEqual(code(b.check, "GET", u, h), "BAD_HEADER")
    def test_redirects_are_never_followed(self):
        self.assertEqual(code(self.broker().request, "GET", f"http://svc.test:{self.port}/redir"), "REDIRECT_REFUSED"); self.assertEqual([h[0] for h in H.hits], ["/redir"])
    def test_response_size_and_timeout_caps(self):
        self.assertEqual(code(self.broker(max_response=100).request, "GET", f"http://svc.test:{self.port}/big"), "RESPONSE_TOO_LARGE")
        self.assertEqual(code(self.broker(timeout=0.3).request, "GET", f"http://svc.test:{self.port}/slow"), "TIMEOUT")
    def test_connection_refused_is_reported_not_raised_raw(self):
        s = serve(H); p = s.server_address[1]; s.shutdown(); s.server_close()
        b = N.NetBroker([N.Allow("http", "svc.test", p, allow_private=True)], resolver=lambda h, q: ["127.0.0.1"]); self.assertEqual(code(b.request, "GET", f"http://svc.test:{p}/"), "CONNECT_FAILED")


class Tls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(); cls.good = cert(cls.d, "tls.test"); cls.other = cert(cls.d, "other.test")
        cls.srv = serve(H, tls=cls.good); cls.port = cls.srv.server_address[1]
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); shutil.rmtree(cls.d, ignore_errors=True)
    def b(self, ca): return N.NetBroker([N.Allow("https", "tls.test", self.port, allow_private=True, ca_file=ca)], resolver=lambda h, p: ["127.0.0.1"])
    def test_https_with_matching_name_and_trusted_ca_works(self): self.assertEqual(self.b(self.good[0]).request("GET", f"https://tls.test:{self.port}/")[0], 200)
    def test_untrusted_certificate_is_rejected(self): self.assertEqual(code(self.b(None).request, "GET", f"https://tls.test:{self.port}/"), "TLS_VERIFY_FAILED")
    def test_certificate_for_another_name_is_rejected_even_if_its_ca_is_trusted(self):
        s = serve(H, tls=self.other); p = s.server_address[1]
        try: b = N.NetBroker([N.Allow("https", "tls.test", p, allow_private=True, ca_file=self.other[0])], resolver=lambda h, q: ["127.0.0.1"]); self.assertEqual(code(b.request, "GET", f"https://tls.test:{p}/"), "TLS_VERIFY_FAILED")
        finally: s.shutdown()
    def test_plain_http_to_an_https_only_entry_is_refused(self): self.assertEqual(code(self.b(self.good[0]).check, "GET", f"http://tls.test:{self.port}/"), "OUTSIDE_ALLOWED_TARGETS")
    def test_non_http_scheme_in_policy_is_rejected(self): self.assertRaises(ValueError, N.NetBroker, [N.Allow("ftp", "x", 1)])


class Proc(unittest.TestCase):
    def setUp(self): self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, True)
    def test_default_policy_allows_nothing(self):
        for a in (["/bin/echo", "x"], ["/bin/true"]): self.assertEqual(code(Pr.ProcBroker().run, a), "PROGRAM_NOT_ALLOWED")
    def test_allowed_program_with_allowed_args_runs(self):
        self.assertEqual(Pr.ProcBroker((Pr.Rule("/bin/echo", (r"[a-z]+",)),)).run(["/bin/echo", "hi"]), (0, b"hi\n", b""))
    def test_arguments_must_match_and_shell_metacharacters_are_refused(self):
        b = Pr.ProcBroker((Pr.Rule("/bin/echo", (r"[a-z]+",)),))
        for a in ("HI", "a;b", "$(id)", "a b", "-n", "", "a\n"): self.assertEqual(code(b.run, ["/bin/echo", a]), "ARG_NOT_ALLOWED", repr(a))
        self.assertEqual(code(Pr.ProcBroker((Pr.Rule("/bin/true"),)).run, ["/bin/true", "x"]), "ARG_NOT_ALLOWED")
    def test_relative_and_bad_argv_are_refused(self):
        b = Pr.ProcBroker((Pr.Rule("/bin/echo", (r".*",)),))
        for a in (["echo", "x"], [], "echo x", ["/bin/echo", 1], ["/bin/echo", "a\x00b"]): self.assertIn(code(b.run, a), ("PROGRAM_NOT_ABSOLUTE", "BAD_ARGV"))
    def test_symlink_cannot_select_a_different_program(self):
        link = os.path.join(self.d, "echo"); os.symlink("/bin/ls", link)
        self.assertEqual(code(Pr.ProcBroker((Pr.Rule("/bin/echo", (r".*",)),)).run, [link]), "PROGRAM_NOT_ALLOWED")
    def test_symlink_to_the_allowed_program_is_the_allowed_program(self):
        link = os.path.join(self.d, "e2"); os.symlink(os.path.realpath("/bin/echo"), link); self.assertEqual(Pr.ProcBroker((Pr.Rule("/bin/echo", (r".*",)),)).run([link, "ok"])[1], b"ok\n")
    def test_environment_is_replaced_not_inherited(self):
        os.environ["BROKER_SECRET"] = "s3cr3t"; self.addCleanup(os.environ.pop, "BROKER_SECRET", None)
        out = Pr.ProcBroker((Pr.Rule("/usr/bin/env"),)).run(["/usr/bin/env"])[1].decode(); self.assertNotIn("BROKER_SECRET", out); self.assertIn("PATH=/usr/bin:/bin", out)
    def test_cwd_must_be_inside_the_rule_root(self):
        sub = os.path.join(self.d, "w"); os.mkdir(sub); b = Pr.ProcBroker((Pr.Rule("/bin/pwd", cwd_root=self.d),))
        self.assertEqual(b.run(["/bin/pwd"], cwd=sub)[1].strip().decode(), os.path.realpath(sub))
        self.assertEqual(code(b.run, ["/bin/pwd"], cwd="/"), "CWD_OUTSIDE_ROOT"); self.assertEqual(code(b.run, ["/bin/pwd"], cwd=self.d + "/../"), "CWD_OUTSIDE_ROOT")
        self.assertEqual(code(Pr.ProcBroker((Pr.Rule("/bin/pwd"),)).run, ["/bin/pwd"], cwd=self.d), "CWD_NOT_ALLOWED")
    def test_timeout_kills_the_whole_process_group(self):
        marker = os.path.join(self.d, "m")
        sc = f"sleep 30 & echo $! > {marker}; wait"; b = Pr.ProcBroker((Pr.Rule("/bin/sh", (r"-c", sc.replace("$", r"\$").replace(".", r"\.")), timeout=0.7),))
        t = time.monotonic(); self.assertEqual(code(b.run, ["/bin/sh", "-c", sc]), "TIMEOUT"); self.assertLess(time.monotonic() - t, 5)
        time.sleep(0.2); pid = int(open(marker).read())
        st = open(f"/proc/{pid}/stat").read().split()[2] if os.path.exists(f"/proc/{pid}") else "gone"
        self.assertIn(st, ("gone", "Z"))          # killed; a zombie only means nothing reaped it (this container's init does not)
    def test_output_flood_is_cut_off(self):
        self.assertEqual(code(Pr.ProcBroker((Pr.Rule("/usr/bin/yes", max_output=1000, timeout=5),)).run, ["/usr/bin/yes"]), "OUTPUT_TOO_LARGE")
    def test_rlimits_are_applied_in_the_child(self):
        b = Pr.ProcBroker((Pr.Rule("/bin/sh", (r"-c", r"ulimit -n"), max_files=23),)); self.assertEqual(b.run(["/bin/sh", "-c", "ulimit -n"])[1].strip(), b"23")
    def test_nonzero_exit_is_returned_not_hidden(self): self.assertEqual(Pr.ProcBroker((Pr.Rule("/bin/false"),)).run(["/bin/false"])[0], 1)
if __name__ == "__main__": unittest.main()
