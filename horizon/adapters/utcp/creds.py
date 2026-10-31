"""Tenant-local credential broker (P5-11, P5-12). The model/manual only ever names a credential REF; the broker injects the secret at send time
if the ref belongs to the caller's tenant AND its bound audience equals the canonical target origin. Secrets never appear in args, logs or results."""
from __future__ import annotations
from urllib.parse import urlsplit


class CredentialError(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


class CredentialBroker:
    def __init__(self): self._s: dict[tuple, dict] = {}
    def put(self, tenant: str, ref: str, secret: str, *, audience_origin: str, scopes=(), header="Authorization", scheme="Bearer") -> None:
        u = urlsplit(audience_origin); self._s[(tenant, ref)] = {"secret": secret, "aud": f"{u.scheme}://{(u.hostname or '').lower()}:{u.port or (443 if u.scheme == 'https' else 80)}", "scopes": frozenset(scopes), "header": header, "scheme": scheme}
    def inject(self, tenant: str, ref: str, target: dict, headers: dict, *, need_scopes=()) -> dict:
        c = self._s.get((tenant, ref))
        if c is None: raise CredentialError("UNKNOWN_REF", "credential not found in this tenant")            # same answer for 'other tenant' and 'missing'
        origin = f"{target['scheme']}://{target['host']}:{target['port']}"
        if c["aud"] != origin: raise CredentialError("AUDIENCE_MISMATCH", "credential is not bound to this destination")
        if not set(need_scopes) <= c["scopes"]: raise CredentialError("SCOPE", "credential lacks required scope")
        if any(k.lower() == c["header"].lower() for k in headers): raise CredentialError("CALLER_SUPPLIED_AUTH", "caller may not supply the credential header")
        return {**headers, c["header"]: f"{c['scheme']} {c['secret']}".strip()}
    @staticmethod
    def scrub(text: str, secrets) -> str:
        for s in secrets:
            if s: text = text.replace(s, "[REDACTED]")
        return text
    def secrets_for(self, tenant: str) -> list[str]: return [v["secret"] for (t, _), v in self._s.items() if t == tenant]
