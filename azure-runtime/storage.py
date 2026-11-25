"""Bounded optimistic SQLite snapshots for the low-volume v2 pilot.
Azure Blob makes the metadata commit conditional; large files stay out of SQLite.
The application emits success only after durable commit.
"""
import hashlib
import hmac
import os
import sqlite3
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import storage_settings
from portal import HEAD
from quarantine import QuarantinePortal

STATE_LIMIT = 16*1024*1024
STATE_AAD = b'Discovery portal starter: encrypted SQLite snapshot v1'
STATE_FILE = 'intake-v2.state'

class StoreUnavailable(Exception): pass

class SnapshotApp:
    def __init__(self,state,objects,key,origin,worker_token,*,exact_cookie_domain=False):
        self.state,self.objects,self.key,self.origin,self.worker_token=state,objects,key,origin,worker_token
        self.aes=AESGCM(key)
        self.exact_cookie_domain=exact_cookie_domain
    def seal(self,raw):
        if not 0<len(raw)<=STATE_LIMIT:
            raise StoreUnavailable()
        nonce=os.urandom(12)
        return nonce+self.aes.encrypt(nonce,raw,STATE_AAD)
    def unseal(self,box):
        if not 28<len(box)<=STATE_LIMIT+28:
            raise StoreUnavailable()
        return self.aes.decrypt(box[:12],box[12:],STATE_AAD)
    @staticmethod
    def error(start):
        data=b'{"error":"storage_unavailable_try_again"}'
        start('503 Service Unavailable',list(HEAD.items())+
            [('Content-Type','application/json'),('Content-Length',str(len(data))),('Retry-After','2')])
        return [data]
    def __call__(self,e,start):
        path=e.get('PATH_INFO','')
        if not path.startswith(('/api/','/internal/')):
            # Static assets have no client data and need no blob round trips.
            p=object.__new__(QuarantinePortal)
            from urllib.parse import urlsplit
            p.host=urlsplit(self.origin).netloc
            return p(e,start)
        if path.startswith('/internal/'):
            auth=e.get('HTTP_AUTHORIZATION','')
            if (e.get('REQUEST_METHOD')!='POST' or e.get('HTTP_ORIGIN') or e.get('HTTP_COOKIE')
                or len(auth)>135 or not hmac.compare_digest(auth.encode('utf-8'), b'Bearer '+self.worker_token.encode('ascii'))):
                data=b'{"error":"not_found"}'
                start('404 Not Found',list(HEAD.items())+[('Content-Type','application/json'),('Content-Length',str(len(data)))])
                return [data]
        try:
            enc,etag=self.state.get_state()
            raw=self.unseal(enc)
            old_digest=hashlib.sha256(raw).digest()
            tmp_base='/dev/shm' if os.path.isdir('/dev/shm') and os.access('/dev/shm',os.W_OK) else None
            with tempfile.TemporaryDirectory(prefix='discovery-intake-',dir=tmp_base) as d:
                db=Path(d)/'state.sqlite'
                db.write_bytes(raw)
                p=QuarantinePortal(db,self.key,self.origin,self.objects,self.worker_token,
                                   exact_cookie_domain=self.exact_cookie_domain)
                pending=[]
                data=p(e,lambda status,headers:pending.extend((status,headers)))
                after=db.read_bytes()
                if not hashlib.sha256(after).digest()==old_digest:
                    self.state.replace_state(self.seal(after),etag)
                start(*pending)
                return data
        except (StoreUnavailable,InvalidTag,sqlite3.Error,OSError,ValueError):
            return self.error(start)

class AzureStateAndObjects:
    def __init__(self,account_url,state_container,quarantine_container,credential):
        from azure.storage.blob import BlobServiceClient
        account_url,state_container,quarantine_container=storage_settings(account_url,state_container,quarantine_container)
        client=BlobServiceClient(account_url,credential=credential,retry_total=1,connection_timeout=4,read_timeout=10)
        self.state=client.get_blob_client(state_container,STATE_FILE)
        self.objects=client.get_container_client(quarantine_container)
    @staticmethod
    def fetch(blob,cap):
        from azure.core.exceptions import AzureError
        try:
            d=blob.download_blob(offset=0,length=cap+1,max_concurrency=1)
            b=d.readall()
        except AzureError:
            raise StoreUnavailable() from None
        if not b or len(b)>cap:
            raise StoreUnavailable()
        return b,d.properties.etag
    def get_state(self):
        return self.fetch(self.state,STATE_LIMIT+28)
    def replace_state(self,body,etag):
        from azure.core import MatchConditions
        from azure.core.exceptions import AzureError
        try:
            self.state.upload_blob(body,overwrite=True,etag=etag,match_condition=MatchConditions.IfNotModified)
        except AzureError:
            raise StoreUnavailable() from None
    def put_once(self,key,body):
        from azure.core.exceptions import AzureError,ResourceExistsError
        try:
            self.objects.get_blob_client(key).upload_blob(body,overwrite=False)
        except ResourceExistsError:
            pass
        except AzureError:
            raise StoreUnavailable() from None
    def get(self,key,cap):
        return self.fetch(self.objects.get_blob_client(key),cap)[0]
