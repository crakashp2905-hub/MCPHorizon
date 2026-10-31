"""Authenticated local socket for evaluator communications (P10-06): Unix socket (0600) plus SO_PEERCRED check of the connecting process uid/gid against an allowlist."""
from __future__ import annotations
import os, socket, socketserver, struct


def peer_cred(sock: socket.socket) -> tuple[int, int, int]:
    if sock.family != socket.AF_UNIX: raise OSError("peer credentials are only meaningful on Unix sockets")     # on TCP the kernel returns zeros, which would read as root
    pid, uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))); return pid, uid, gid


class PeerAuthUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path, handler, *, allowed_uids: set[int]):
        self.allowed_uids, self.rejected = set(allowed_uids), 0
        if os.path.exists(path): os.unlink(path)
        old = os.umask(0o177)
        try: super().__init__(path, handler)
        finally: os.umask(old)
        os.chmod(path, 0o600)

    def verify_request(self, request, client_address):
        try: _, uid, _ = peer_cred(request)
        except (OSError, AttributeError): self.rejected += 1; return False                # cannot establish identity => refuse
        if uid not in self.allowed_uids: self.rejected += 1; return False
        return True
