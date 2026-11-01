#!/usr/bin/env python3
"""Inside a fresh network namespace the loopback interface is DOWN, which makes loopback-only synthetic services unreachable (and a probe that cannot reach its service would otherwise read as 'no exposure'). This wrapper brings `lo` up with an ioctl (no `ip` binary needed) and execs the command. It adds no other interface, so external addresses stay unreachable."""
import fcntl, os, socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
ifr = struct.pack("16sH14x", b"lo", 0); fl = struct.unpack("16sH14x", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]; fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14x", b"lo", fl | IFF_UP)); s.close()
os.execvp(sys.argv[1], sys.argv[1:])
