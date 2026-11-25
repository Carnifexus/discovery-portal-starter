"""Optional client for an independently installed local ClamAV daemon."""
import re, socket, struct, time
from datetime import datetime, timezone
from pathlib import Path

LIMIT=2*1024*1024

def call(path,cmd,data=None):
    if not Path(path).is_absolute():raise ValueError("Unix socket path must be absolute")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(8);s.connect(path);s.sendall(cmd)
        if data is not None:
            for i in range(0,len(data),65536):
                c=data[i:i+65536];s.sendall(struct.pack("!I",len(c))+c)
            s.sendall(b"\0"*4)
        out=b""
        while len(out)<4096 and not out.endswith(b"\0"):
            n=s.recv(1024)
            if not n:break
            out+=n
    return out

def verdict(path,data):
    if not path or not 0 < len(data) <= LIMIT:return None
    try:
        version=call(path,b"zVERSION\0")
        found=re.fullmatch(rb"ClamAV [^/\r\n\x00]+/[0-9]+/([^\r\n\x00]{24})\0",version)
        if not found:return None
        age=time.time()-datetime.strptime(found[1].decode("ascii"),"%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc).timestamp()
        if not -300<=age<=3*86400:return None
        ans=call(path,b"zINSTREAM\0",data)
        if ans==b"stream: OK\0":return "clean"
        if re.fullmatch(rb"stream: [^\x00\r\n]{1,1000} FOUND\0",ans):return "blocked"
    except (OSError,ValueError,UnicodeError):return None
    return None
