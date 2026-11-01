"""URL canonicalization corpus (P44-03/11): (input, expected canonical URL or None for UNRESOLVABLE). Local fixtures only."""
CASES = [
 ("http://Partner.TEST./x", "http://partner.test/x"), ("http://partner.test:80/a/../b", "http://partner.test/b"), ("http://PARTNER.test:8080/a/./b?q=1#frag", "http://partner.test:8080/a/b?q=1"),
 ("http://2130706692:8080/", "http://127.0.1.4:8080/"), ("http://0x7f000104:8080/", "http://127.0.1.4:8080/"), ("http://0177.0.1.4:8080/", "http://127.0.1.4:8080/"), ("http://127.1:8080/", "http://127.0.0.1:8080/"),
 ("http://[::ffff:127.0.1.4]:8080/", "http://127.0.1.4:8080/"), ("http://[::ffff:7f00:104]:8080/", "http://127.0.1.4:8080/"), ("http://[::1]:9/", "http://[::1]:9/"),
 ("http://partner.test@evil.test:8080/", "http://evil.test:8080/"), ("http://evil.test%2e:8080/", "http://evil.test:8080/"), ("http://pa%72tner.test/", "http://partner.test/"), ("http://bücher.test/", "http://xn--bcher-kva.test/"),
 ("https://partner.test/", "https://partner.test/"), ("https://partner.test:443/", "https://partner.test/"), ("http://partner.test:/x", "http://partner.test/x"),
 ("http://evil\\@partner.test/", None), ("http://a..b/", None), ("ftp://x/", None), ("http://256.1.1.1/", None), ("http://0x100000000/", None), ("http://1.2.3.4.5/", None), ("http://host.123/", None),
 ("http://par tner.test/", None), ("http://partner.test/\x00", None), ("", None), ("partner.test/x", None), ("http:///x", None), ("http://partner.test:99999/", None), ("http://partner.test:0/", None), ("http://[::1/", None), ("http://[zz::1]/", None),
 ("http://" + "a" * 3000 + ".test/", None), ("javascript://partner.test/", None), ("http://exa_mple.test/", None), ("http://-bad.test/", None),
]
