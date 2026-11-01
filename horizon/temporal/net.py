"""Mock name resolution and redirects (P52-06). No real network: a dictionary of host -> addresses and host -> redirect target, changed by scenario steps (DNS rebinding, open redirect)."""
class Net:
    def __init__(self): self.dns = {"partner.test": ["10.0.0.5"], "intra.test": ["10.0.1.1"], "evil.test": ["10.6.6.6"]}; self.redirects = {}; self.lookups = 0
    def resolve(self, host): self.lookups += 1; return list(self.dns.get(host, []))
    def rebind(self, host, ips): self.dns[host] = list(ips)
    def redirect(self, host, to): self.redirects[host] = to
    def connect(self, host, pin=None): return pin if pin else (self.resolve(host) or [None])[0]
    def redirected(self, host): return self.redirects.get(host)
