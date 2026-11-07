"""One SNTP client query (mode 3); prints the server time. Usage: ntp_query.py <server>"""

import socket
import struct
import sys
import time

server = sys.argv[1] if len(sys.argv) > 1 else "ntp.aliyun.com"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
now = time.time() + 2208988800
s.sendto(b"\x23" + bytes(39) + struct.pack("!II", int(now), int((now % 1) * 2**32)), (server, 123))
data, _ = s.recvfrom(512)
print(server, time.ctime(struct.unpack("!I", data[40:44])[0] - 2208988800))
