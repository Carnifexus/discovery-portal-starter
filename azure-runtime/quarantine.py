"""An isolated, asynchronous intake path. No scan result, no release."""
import base64
import hashlib
import hmac
import re
import time
from pathlib import PurePosixPath

from portal import FILE_CAP, HEAD, ID, MATTER_BYTES, HTTPError, Portal, dump, new, req, may_attach
from screening import ALLOWED, MAX_BYTES, Rejected, filename, declared_type

SCAN = """
CREATE TABLE IF NOT EXISTS scan (
  fid TEXT PRIMARY KEY REFERENCES file(id),
  state TEXT NOT NULL CHECK(state IN ('pending','scanning','clean','blocked')),
  lease TEXT, deadline INTEGER
);
CREATE INDEX IF NOT EXISTS scan_state_idx ON scan(state,deadline);
"""
GRACE = 180

class QuarantinePortal(Portal):
    def __init__(self, db, key, origin, objects, token, *, init=False, exact_cookie_domain=False):
        if not re.fullmatch(r'[A-Za-z0-9_-]{43,128}', token):
            raise ValueError('Separate scanner token required')
        self.objects = objects
        self.worker_token = token.encode('ascii')
        super().__init__(db, key, origin, None, init=init, exact_cookie_domain=exact_cookie_domain)
        if init:
            with self.tx(True) as c:
                for statement in SCAN.split(';'):
                    if statement.strip():
                        c.execute(statement)

    def upload(self, e, m, r):
        try:
            name, ext = filename(e.get('HTTP_X_FILE_NAME',''))
        except (UnicodeError, ValueError) as ex:
            raise HTTPError(415, str(ex) if isinstance(ex,Rejected) else 'invalid_filename') from None
        with self.tx(True) as c:
            u,t = self.session(e,c)
            self.csrf(e,u)
            self.matter(c,u,m)
            q = self.row(c,m,r,u)
            req(u['role']=='client',403,'not_permitted')
            req(may_attach(q['kind'],self.read(m,'request:'+r,q['data']),self.restricted(c,m)),409,'not_a_document_request')
            self.intake_open(c,r)
            req(self.rate(c,self.index(b'upload:'+u['id'].encode()),300,15),429,'try_again_later')
        raw = self.bytes(e,MAX_BYTES,'application/octet-stream')
        try:
            declared_type(raw,ext)
        except Rejected as ex:
            raise HTTPError(415,str(ex)) from None
        sha = hashlib.sha256(raw).hexdigest()
        dedup = self.index(dump(['original',m,r,sha]))
        # Name and byte-encryption scope are opaque and deterministic for retries.
        obj = dedup.hex()
        with self.tx(True) as c:
            u,_ = self.session_hash(c,t)
            self.matter(c,u,m)
            self.row(c,m,r,u)
            self.intake_open(c,r)
            prior = c.execute('SELECT f.id,s.state FROM file f JOIN scan s ON s.fid=f.id WHERE f.mid=? AND f.rid=? AND f.dedup=?',(m,r,dedup)).fetchone()
            if prior:
                return 200, {'fileId':prior['id'],'status':prior['state']}
            count,used = c.execute('SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM file WHERE mid=?',(m,)).fetchone()
            req(count<FILE_CAP and used+len(raw)<=MATTER_BYTES,413,'matter_upload_limit')
            self.objects.put_once(obj,self.box(m,'quarantine:'+obj,raw))
            fid = new()
            meta = {'name':name,'mediaType':ALLOWED[ext],'sha256':sha}
            c.execute('INSERT INTO file VALUES(?,?,?,?,?,?,?,?,?)',
                     (fid,m,r,u['id'],len(raw),dedup,self.protect(m,'file-meta:'+fid,meta),b'',int(time.time())))
            c.execute("INSERT INTO scan VALUES(?, 'pending', NULL, NULL)",(fid,))
            return 201, {'fileId':fid,'status':'pending'}

    def original(self,m,f,meta):
        obj=bytes(f['dedup']).hex()
        raw=self.open(m,'quarantine:'+obj,self.objects.get(obj,MAX_BYTES+28))
        req(len(raw)==f['bytes'] and hmac.compare_digest(hashlib.sha256(raw).hexdigest(),meta['sha256']),
            503,'integrity_check_failed')
        return raw

    def visible_file(self,c,u,fid):
        row = c.execute('SELECT state FROM scan WHERE fid=?',(fid,)).fetchone()
        return row is not None and row['state']=='clean'

    def held_files(self,c,u,m):
        # Counsel sees counts only. Clients can see status of their own submissions.
        result={}
        filt,args=self.scope_sql(c,u,m,'f.rid')
        for f in c.execute("""SELECT f.id,f.rid,f.aid,f.meta,s.state FROM file f JOIN scan s
            ON s.fid=f.id WHERE f.mid=? AND s.state!='clean'"""+filt,(m,*args)):
            if u['role']=='client' and f['aid']!=u['id']:
                continue
            item={'state':'blocked' if f['state']=='blocked' else 'pending'}
            if u['role']=='client':
                item['name']=self.read(m,'file-meta:'+f['id'],f['meta'])['name']
            result.setdefault(f['rid'],[]).append(item)
        return result

    def matter_payload(self,c,u,m,label):
        p=super().matter_payload(c,u,m,label)
        held=self.held_files(c,u,m)
        for q in p['requests']:
            q['quarantine']=held.get(q['id'],[])
        return p

    def scan_api(self,e,start):
        req(e.get('REQUEST_METHOD')=='POST' and not e.get('HTTP_ORIGIN') and not e.get('HTTP_COOKIE'),404,'not_found')
        auth=e.get('HTTP_AUTHORIZATION','')
        req(len(auth)<=135 and hmac.compare_digest(auth.encode('utf-8'),b'Bearer '+self.worker_token),404,'not_found')
        payload=self.payload(e)
        now=int(time.time())
        if e['PATH_INFO']=='/internal/scan/claim':
            req(payload=={})
            with self.tx(True) as c:
                f=c.execute("""SELECT f.* FROM scan s JOIN file f ON f.id=s.fid
                    WHERE s.state='pending' OR (s.state='scanning' AND s.deadline<?)
                    ORDER BY f.created,f.id LIMIT 1""",(now,)).fetchone()
                if not f:
                    return self.reply(start,200,b'{}')
                m,fid=f['mid'],f['id']
                meta=self.read(m,'file-meta:'+fid,f['meta'])
                raw=self.original(m,f,meta)
                lease=new()
                c.execute("UPDATE scan SET state='scanning',lease=?,deadline=? WHERE fid=?",(lease,now+GRACE,fid))
                return self.reply(start,200,dump({'id':fid,'lease':lease,'sha256':meta['sha256'],
                    'extension':PurePosixPath(meta['name']).suffix.lower(),'bytes':base64.b64encode(raw).decode('ascii')}))
        if e['PATH_INFO']=='/internal/scan/verdict':
            req(type(payload) is dict and set(payload)=={'id','lease','sha256','verdict'})
            fid,lease,sha,verdict=(payload[k] for k in ('id','lease','sha256','verdict'))
            req(type(fid) is str and ID.fullmatch(fid) and type(lease) is str and ID.fullmatch(lease)
                and type(sha) is str and re.fullmatch('[a-f0-9]{64}',sha) and verdict in ('clean','blocked'))
            with self.tx(True) as c:
                f=c.execute('SELECT f.*,s.state,s.lease,s.deadline FROM file f JOIN scan s ON s.fid=f.id WHERE f.id=?',(fid,)).fetchone()
                req(f and f['lease']==lease,409,'stale_scan')
                meta=self.read(f['mid'],'file-meta:'+fid,f['meta'])
                req(hmac.compare_digest(meta['sha256'],sha),409,'stale_scan')
                if f['state']==verdict:
                    return self.reply(start,200,b'{}')
                req(f['state']=='scanning' and now<=f['deadline'],409,'stale_scan')
                if verdict=='clean':
                    self.original(f['mid'],f,meta)
                    meta['screening']='scanner_and_type_checks_passed'
                    c.execute('UPDATE file SET meta=? WHERE id=?',(self.protect(f['mid'],'file-meta:'+fid,meta),fid))
                    self.audit(c,f['mid'],{'id':f['aid']},'file_received',fid)
                c.execute('UPDATE scan SET state=?,deadline=NULL WHERE fid=?',(verdict,fid))
                return self.reply(start,200,b'{}')
        raise HTTPError(404,'not_found')

    def __call__(self,e,start):
        if e['PATH_INFO'].startswith('/internal/'):
            try:
                req(e.get('HTTP_HOST')==self.host,404,'not_found')
                return self.scan_api(e,start)
            except HTTPError as ex:
                return self.reply(start,ex.status,dump({'error':ex.code}))
            except (ValueError,TypeError,KeyError,RecursionError):
                return self.reply(start,400,b'{"error":"invalid_request"}')
        return super().__call__(e,start)
