"""Outbound-only scanner; no browser user credentials or direct Azure Storage access."""
import argparse
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import ssl
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path
from config import deployment_host

from screening import ALLOWED,MAX_BYTES,Clamd,Rejected,ScannerOffline,screened

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*_args,**_kwargs): return None

def restricted_secret(path):
    p=Path(path)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        st=os.fstat(f.fileno())
        if st.st_uid!=os.getuid() or not stat.S_ISREG(st.st_mode) or st.st_mode&0o077:
            raise ValueError('Secret must be a private, regular, owner-only file')
        token=f.read(130).strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{43,128}',token):
        raise ValueError('Invalid worker credential')
    return token

class Remote:
    def __init__(self,origin,token):
        deployment_host(origin)
        self.origin=origin
        self.token=token
        self.http=urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}),
                                              urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    def call(self,part,body,limit):
        req=urllib.request.Request(self.origin+'/internal/scan/'+part,
           data=json.dumps(body,separators=(',',':')).encode('utf8'),method='POST',
           headers={'Content-Type':'application/json','Authorization':'Bearer '+self.token})
        with self.http.open(req,timeout=30) as response:
            raw=response.read(limit+1)
            if len(raw)>limit:
                raise ValueError('Invalid scan response')
            return json.loads(raw)
def process(remote,scanner):
    scanner.require_fresh_database()  # Do not even claim while the local scanner is down.
    work=remote.call('claim',{},(MAX_BYTES*4//3)+1024)
    if not work:
        return False
    if (set(work)!={'id','lease','sha256','extension','bytes'}
        or work['extension'] not in ALLOWED
        or not re.fullmatch(r'[a-f0-9]{64}',work['sha256'])):
        raise ValueError('Invalid scan response')
    data=base64.b64decode(work['bytes'],validate=True)
    if not 0<len(data)<=MAX_BYTES or not hmac.compare_digest(hashlib.sha256(data).hexdigest(),work['sha256']):
        raise ValueError('Original did not match receipt')
    try:
        screened(data,work['extension'],scanner)
        verdict='clean'
    except Rejected:
        verdict='blocked'
    remote.call('verdict',{k:work[k] for k in ('id','lease','sha256')}|{'verdict':verdict},1024)
    return True

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--origin',required=True)
    parser.add_argument('--token-file',required=True)
    parser.add_argument('--socket',required=True)
    parser.add_argument('--lock',required=True)
    args=parser.parse_args()
    os.umask(0o077)
    guard=os.open(args.lock,os.O_NOFOLLOW|os.O_CREAT|os.O_RDWR,0o600)
    try:
        fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        return 0
    try:
        token=restricted_secret(args.token_file)
        remote=Remote(args.origin,token)
        scanner=Clamd(args.socket)
        for _ in range(3):
            if not process(remote,scanner):
                break
        return 0
    except (ScannerOffline,ValueError,TypeError,OSError):
        print('Discovery scanner unavailable; unverified uploads remain in quarantine.',file=sys.stderr)
        return 75
    finally:
        os.close(guard)
if __name__=='__main__':
    sys.exit(main())
