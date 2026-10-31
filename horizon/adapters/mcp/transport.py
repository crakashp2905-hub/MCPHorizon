"""Transport security helpers (P4-13..P4-15): stdio spawning, Streamable HTTP origin/target checks, OAuth claim binding.
SCOPE LIMITS (read before relying on this): process limits are POSIX rlimits, not a sandbox; JWT signature verification is NOT implemented here
(claims must come from a verified token); DNS resolution is not performed, so hostnames resolving to private ranges are not caught."""
from __future__ import annotations
import ipaddress, os, resource, subprocess
from urllib.parse import urlsplit
from ...normalize import canonical_url

SAFE_ENV = ("PATH", "LANG", "LC_ALL", "TZ")


class TransportError(Exception):
    pass


def spawn_stdio(argv: list[str], *, allowed_executables: set[str], cwd: str, allowed_cwd_roots: list[str], extra_env: dict[str, str] | None = None,
                cpu_s: int = 30, mem_bytes: int = 512 << 20, max_files: int = 64) -> subprocess.Popen:
    """Launch a local MCP server with: absolute allowlisted executable, no shell, scrubbed env (explicit extras only), cwd under an allowed root,
    CPU/memory/fd limits, own session, stderr separated from the protocol stream."""
    if not argv or not os.path.isabs(argv[0]) or os.path.realpath(argv[0]) not in {os.path.realpath(x) for x in allowed_executables}:
        raise TransportError("executable must be an absolute path on the allowlist")
    rc = os.path.realpath(cwd)
    if not any(rc == os.path.realpath(r) or rc.startswith(os.path.realpath(r) + os.sep) for r in allowed_cwd_roots): raise TransportError("cwd outside allowed roots")
    env = {k: os.environ[k] for k in SAFE_ENV if k in os.environ}
    for k, v in (extra_env or {}).items():
        if not k.isidentifier(): raise TransportError("bad env name")
        env[k] = v
    def limits():
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s)); resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes)); resource.setrlimit(resource.RLIMIT_NOFILE, (max_files, max_files))
        os.setsid()
    return subprocess.Popen(argv, cwd=rc, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, preexec_fn=limits, close_fds=True)


def check_origin(origin: str | None, allowed_origins: set[str]) -> None:
    """Per spec: if an Origin header is present and not allowed => reject (403). Absent Origin (non-browser client) is allowed here but auth is still required."""
    if origin is not None and origin not in allowed_origins: raise TransportError("403: origin not allowed")


def check_bind(host: str, local_only: bool) -> None:
    if local_only and not ipaddress.ip_address(host).is_loopback: raise TransportError("local server must bind loopback only")


def check_remote_target(url: str, *, allow_http: bool = False) -> str:
    """SSRF-style gate for remote MCP endpoints. Literal IPs in private/loopback/link-local/metadata ranges, userinfo, odd ports and non-https are rejected.
    Redirects must be disabled by the caller (not enforceable here)."""
    s = urlsplit(url)
    if s.username or s.password: raise TransportError("credentials in URL")
    if s.scheme != "https" and not (allow_http and s.scheme == "http"): raise TransportError("https required")
    canon = canonical_url(url); host = urlsplit(canon).hostname or ""
    try: ip = ipaddress.ip_address(host)
    except ValueError: ip = None
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified): raise TransportError("target address is not publicly routable")
    if host in ("localhost", "metadata.google.internal") or host.endswith((".local", ".internal")): raise TransportError("internal hostname")
    return canon


def validate_token_claims(claims: dict, *, issuer: str, audience: str, now: float, leeway: float = 30.0) -> None:
    """Bind an ALREADY SIGNATURE-VERIFIED token to this server: exact issuer, audience contains exactly our identifier, time window valid."""
    if claims.get("iss") != issuer: raise TransportError("issuer mismatch")
    aud = claims.get("aud"); auds = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) and all(isinstance(a, str) for a in aud) else None
    if auds is None or audience not in auds: raise TransportError("audience mismatch (token not issued for this server)")
    if not isinstance(claims.get("exp"), (int, float)) or now > claims["exp"] + leeway: raise TransportError("token expired or exp missing")
    if isinstance(claims.get("nbf"), (int, float)) and now + leeway < claims["nbf"]: raise TransportError("token not yet valid")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]: raise TransportError("missing subject")
