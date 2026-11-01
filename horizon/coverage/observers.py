"""Independent host-side observers (separate processes). None of them import enforcement code. Loopback / local paths only; synthetic canary only."""
from __future__ import annotations
import json, os, socket, subprocess, sys, time
from ..counterfactual.commit import receipt as _receipt           # the FS observer is the P41 read-only receipt process
from ..runtime.receiver import Receiver, CANARY, VARIANTS                # the TCP observer is the P25 receiver process

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FsObserver:
    """Hash manifest of a directory taken by a separate process before/after; reports created/changed/removed paths."""
    def __init__(self, root): self.root, self.base = root, None
    def arm(self): self.base = _receipt("files", self.root)
    def changes(self):
        now = _receipt("files", self.root); b = self.base or {}
        return sorted([k for k in now if k not in b] + [k for k in now if k in b and now[k] != b[k]] + [k for k in b if k not in now])


class UdpObserver:
    """Separate process bound to a UDP loopback port; journals one JSON line per datagram."""
    def __init__(self, port, workdir): self.port, self.journal = port, os.path.join(workdir, "udp.jsonl"); open(self.journal, "w").close()
    def __enter__(self):
        self.ready = self.journal + ".ready"
        code = ("import socket,sys,json\nS=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);S.bind(('127.0.0.1',int(sys.argv[1])));open(sys.argv[3],'w').write('1')\n"
                "C=%r\nwhile True:\n d,_=S.recvfrom(65535);open(sys.argv[2],'a').write(json.dumps({'bytes':len(d),'has_canary':C in d})+'\\n')\n" % CANARY)
        self.p = subprocess.Popen([sys.executable, "-I", "-c", code, str(self.port), self.journal, self.ready], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(self.ready): return self
            time.sleep(.05)
        raise RuntimeError("udp observer did not start")
    def __exit__(self, *a): self.p.kill(); self.p.wait()
    def rows(self): time.sleep(.15); return [json.loads(l) for l in open(self.journal).read().splitlines() if l.strip()]


class ProcSampler:
    """Separate process that polls /proc every `period` seconds for any process whose cmdline contains a marker; journals each distinct pid once. A SAMPLER: it can miss short-lived processes (that is a measured blind spot)."""
    def __init__(self, marker, workdir, period=0.02): self.marker, self.period, self.journal = marker, period, os.path.join(workdir, "proc.jsonl"); open(self.journal, "w").close()
    def __enter__(self):
        ready = self.journal + ".ready"
        code = ("import os,sys,time,json\nm=sys.argv[1].encode();per=float(sys.argv[2]);seen=set();open(sys.argv[4],'w').write('1')\nwhile True:\n"
                " for d in os.listdir('/proc'):\n"
                "  if d.isdigit() and d not in seen:\n"
                "   try: c=open('/proc/'+d+'/cmdline','rb').read()\n"
                "   except OSError: continue\n"
                "   if m in c and d!=str(os.getpid()): seen.add(d);open(sys.argv[3],'a').write(json.dumps({'pid':int(d)})+'\\n')\n"
                " time.sleep(per)\n")
        self.p = subprocess.Popen([sys.executable, "-I", "-c", code, self.marker, str(self.period), self.journal, ready], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(ready): return self
            time.sleep(.05)
        raise RuntimeError("sampler did not start")
    def __exit__(self, *a): self.p.kill(); self.p.wait()
    def rows(self): time.sleep(.1); return [json.loads(l) for l in open(self.journal).read().splitlines() if l.strip()]
