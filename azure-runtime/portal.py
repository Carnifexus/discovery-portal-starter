"""Separate private intake portal. No dependency on any existing matter or deployment."""
import base64, hashlib, hmac, json, os, re, secrets, sqlite3, threading, time
from contextlib import contextmanager
from http.cookies import SimpleCookie, CookieError
from pathlib import Path
from urllib.parse import urlsplit, quote
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from config import deployment_host
from screening import ALLOWED, MAX_BYTES, Clamd, Rejected, ScannerOffline, filename, screened

ASSETS=Path(__file__).resolve().parent/'web'
COOKIE='__Host-intake-v2'
AZURE_COOKIE='__Secure-discovery-intake-azure'
TOKEN=re.compile(r'[A-Za-z0-9_-]{43}\Z')
ID=re.compile(r'[0-9a-f]{32}\Z')
USER=re.compile(r'[a-z0-9][a-z0-9_.-]{2,63}\Z')
STATUS={200:'OK',201:'Created',400:'Bad Request',401:'Unauthorized',403:'Forbidden',404:'Not Found',
        409:'Conflict',413:'Content Too Large',415:'Unsupported Media Type',429:'Too Many Requests',
        500:'Internal Server Error',503:'Service Unavailable'}
FILE_CAP=25
MATTER_BYTES=150*1024*1024
RESPONSES={'answer','unknown','clarification','true_input','false_input','partial_input'}
FACT_CHOICES={'true_input','false_input','partial_input'}
DOCUMENT_STATEMENTS={'never_existed','cannot_find','not_kept'}
DOCUMENT_PROGRESS={'searching','help'}
RESPONSES |= DOCUMENT_STATEMENTS
VISIBLE_ACTIVITY={'matter_created','file_received','batch_submitted','request_added','follow-up','file_reviewed','review','client_access_revoked','request_hidden','request_reopened','document_status','document_progress','document_help_reply'}
HEAD={
 'Cache-Control':'private, no-store', 'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
 'X-Frame-Options':'DENY','X-Robots-Tag':'noindex, nofollow, noarchive',
 'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
 'Strict-Transport-Security':'max-age=31536000',
 'Cross-Origin-Resource-Policy':'same-origin',
 'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self';"
}
SCHEMA="""
CREATE TABLE IF NOT EXISTS appcheck (id INTEGER PRIMARY KEY CHECK(id=1), ciphertext BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS matter (id TEXT PRIMARY KEY, label BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS account (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, role TEXT NOT NULL CHECK(role IN ('client','counsel')), mid TEXT REFERENCES matter(id), salt BLOB NOT NULL, verifier BLOB NOT NULL, active INT NOT NULL DEFAULT 1, epoch INT NOT NULL DEFAULT 0, CHECK((role='client')=(mid IS NOT NULL)));
CREATE TABLE IF NOT EXISTS session (token BLOB PRIMARY KEY, aid TEXT NOT NULL REFERENCES account(id), csrf BLOB NOT NULL, csrf_box BLOB NOT NULL, epoch INT NOT NULL, until INT NOT NULL);
CREATE TABLE IF NOT EXISTS request (id TEXT PRIMARY KEY, mid TEXT NOT NULL REFERENCES matter(id), ord INTEGER NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('question','documents','both')), data BLOB NOT NULL, UNIQUE(mid,ord));
CREATE TABLE IF NOT EXISTS batch (id TEXT PRIMARY KEY, mid TEXT NOT NULL REFERENCES matter(id), aid TEXT NOT NULL REFERENCES account(id), created INT NOT NULL);
CREATE TABLE IF NOT EXISTS discovery_access (mid TEXT PRIMARY KEY REFERENCES matter(id));
CREATE TABLE IF NOT EXISTS assignment (rid TEXT PRIMARY KEY REFERENCES request(id), root TEXT NOT NULL REFERENCES request(id), aid TEXT NOT NULL REFERENCES account(id), UNIQUE(root,aid));
CREATE INDEX IF NOT EXISTS assignments_by_recipient ON assignment(aid,rid);
CREATE TABLE IF NOT EXISTS production_update (id TEXT PRIMARY KEY, rid TEXT NOT NULL REFERENCES request(id), aid TEXT NOT NULL REFERENCES account(id), kind TEXT NOT NULL CHECK(kind IN ('searching','help')), data BLOB NOT NULL, created INT NOT NULL, reply BLOB);
CREATE INDEX IF NOT EXISTS production_updates_by_request ON production_update(rid,created);
CREATE TABLE IF NOT EXISTS client_hidden (rid TEXT PRIMARY KEY REFERENCES request(id), created INT NOT NULL);
CREATE TABLE IF NOT EXISTS answer (rid TEXT PRIMARY KEY REFERENCES request(id), bid TEXT NOT NULL REFERENCES batch(id), data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS draft (aid TEXT NOT NULL REFERENCES account(id), rid TEXT NOT NULL REFERENCES request(id), data BLOB NOT NULL, PRIMARY KEY(aid,rid));
CREATE TABLE IF NOT EXISTS followup (rid TEXT PRIMARY KEY REFERENCES request(id), data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS file (id TEXT PRIMARY KEY, mid TEXT NOT NULL REFERENCES matter(id), rid TEXT NOT NULL REFERENCES request(id), aid TEXT NOT NULL REFERENCES account(id), bytes INT NOT NULL, dedup BLOB NOT NULL, meta BLOB NOT NULL, data BLOB NOT NULL, created INT NOT NULL, UNIQUE(mid,rid,dedup));
CREATE TABLE IF NOT EXISTS file_review (fid TEXT PRIMARY KEY REFERENCES file(id), status TEXT NOT NULL CHECK(status IN ('accepted','needs-more','held')), notes BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS request_review (rid TEXT PRIMARY KEY REFERENCES request(id), status TEXT NOT NULL CHECK(status IN ('complete','needs-more','held')), notes BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, mid TEXT NOT NULL REFERENCES matter(id), aid TEXT NOT NULL REFERENCES account(id), event TEXT NOT NULL, item TEXT NOT NULL, created INT NOT NULL);
CREATE TABLE IF NOT EXISTS rate (slot INT NOT NULL, tag BLOB NOT NULL, count INT NOT NULL, PRIMARY KEY(slot,tag));
CREATE INDEX IF NOT EXISTS files_by_request ON file(mid,rid);
CREATE INDEX IF NOT EXISTS audit_by_matter ON audit(mid,seq);
"""

class HTTPError(Exception):
    def __init__(self,status,code): self.status=status;self.code=code
def req(ok,status=400,code='invalid_request'):
    if not ok: raise HTTPError(status,code)
def new(): return secrets.token_hex(16)
def dump(x): return json.dumps(x,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf8')
def digest(x): return hashlib.sha256(x.encode('ascii')).digest()
def clean(x,maxlen=2000,empty=False):
    req(isinstance(x,str) and len(x)<=maxlen and (empty or bool(x.strip())) and not any(ord(c)<32 and c not in '\n\t\r' for c in x))
    return x.strip()
def exact(o,*keys): req(type(o) is dict and set(o)==set(keys))
def pwd(p,salt): return hashlib.scrypt(p.encode('utf8'),salt=salt,n=32768,r=8,p=1,dklen=32,maxmem=64*1024*1024)
def validpass(p): return isinstance(p,str) and 16<=len(p)<=256 and len(p.encode('utf8'))<=320
def pairs(xs):
    o={}
    for k,v in xs:
        req(k not in o);o[k]=v
    return o

def request_category(kind,title,explicit=None):
    if explicit is not None:
        req(explicit in ('rog','rpd','rfa') and (explicit=='rpd')==(kind=='documents') and (explicit!='rfa' or kind=='question'))
        return explicit
    if kind=='documents':return 'rpd'
    if title.casefold().startswith('request for admission'):return 'rfa'
    return 'rog'

def request_definitions(items):
    req(type(items) is list and len(items)<=30)
    out=[]; terms=set()
    for val in items:
        exact(val,'term','source','exact','plain')
        d={key:clean(val[key],limit) for key,limit in (
            ('term',150),('source',160),('exact',1800),('plain',800))}
        term=d['term'].casefold()
        req(term not in terms); terms.add(term); out.append(d)
    return out

def may_attach(kind,item,flexible):
    return kind!='question' or (flexible and request_category(kind,item['title'],item.get('category'))=='rog')

class Portal:
    def __init__(self,db,key,origin,scanner,*,demo=False,init=False,exact_cookie_domain=False):
        u=urlsplit(origin); req(u.scheme=='https' or (demo and u.scheme=='http' and u.hostname in ('127.0.0.1','localhost')))
        req(bool(u.hostname) and not (u.path or u.query or u.fragment or u.username or u.password))
        if exact_cookie_domain:
            deployment_host(origin)
        self.exact_cookie_domain=exact_cookie_domain
        req(isinstance(key,bytes) and len(key)==32)
        self.origin=origin;self.host=u.netloc;self.db=Path(db);self.aes=AESGCM(key)
        self.tagkey=hmac.digest(key,b'guided-intake-v2/special-index', 'sha256')
        self.scanner=scanner; self.scan_slots=threading.BoundedSemaphore(2)
        if not init and not self.db.is_file(): raise ValueError('Configure a separate database first')
        self.dummy_salt=secrets.token_bytes(16)
        with self.tx(True) as c:
            if init:
                for st in SCHEMA.split(';'):
                    if st.strip():c.execute(st)
            row=c.execute('SELECT ciphertext FROM appcheck WHERE id=1').fetchone()
            if not row:
                if not init:raise ValueError('Portal is not initialized')
                c.execute('INSERT INTO appcheck VALUES(1,?)',(self.box('app','identity',b'independent-intake-v2'),))
            elif self.open('app','identity',row[0])!=b'independent-intake-v2':
                raise ValueError('Wrong portal database or encryption key')

    @contextmanager
    def tx(self,write=False):
        c=sqlite3.connect(self.db,timeout=8); c.row_factory=sqlite3.Row
        try:
            c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA busy_timeout=8000')
            c.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            yield c; c.commit()
        except BaseException: c.rollback();raise
        finally:c.close()

    def box(self,scope,what,b):
        n=secrets.token_bytes(12);return n+self.aes.encrypt(n,b,dump(['intake-v2',scope,what]))
    def open(self,scope,what,b):
        return self.aes.decrypt(b[:12],b[12:],dump(['intake-v2',scope,what]))
    def protect(self,scope,what,p):return self.box(scope,what,dump(p))
    def read(self,scope,what,b):return json.loads(self.open(scope,what,b))
    def index(self,s):return hmac.digest(self.tagkey,s,'sha256')

    def create_matter(self,c,title):
        m=new();c.execute('INSERT INTO matter VALUES(?,?)',(m,self.protect(m,'matter',clean(title,120))));return m
    def provision(self,c,u,b):
        exact(b,'title','username','password','requests',*(['assignAll'] if 'assignAll' in b else []))
        assign_all=b.get('assignAll',True)
        req(type(assign_all) is bool)
        name=b['username']; requests=b['requests']
        req(isinstance(name,str) and USER.fullmatch(name) and validpass(b['password']))
        req(type(requests) is list and 1<=len(requests)<=100)
        req(c.execute('SELECT 1 FROM account WHERE username=?',(name,)).fetchone() is None,409,'username_unavailable')
        mid=self.create_matter(c,b['title'])
        for item in requests:
            exact(item,'title','details','kind',*[key for key in ('category','definitions') if isinstance(item,dict) and key in item])
            self.add_request(c,mid,item['title'],item['details'],item['kind'],item.get('definitions',[]),item.get('category'))
        aid=self.register(c,name,b['password'],'client',mid)
        c.execute('INSERT INTO discovery_access VALUES(?)',(mid,))
        if assign_all:c.execute('INSERT INTO assignment SELECT id,id,? FROM request WHERE mid=?',(aid,mid))
        self.audit(c,mid,u,'matter_created',mid)
        return {'id':mid}

    def register(self,c,name,password,role,mid):
        req(USER.fullmatch(name) and validpass(password));aid=new();salt=secrets.token_bytes(16)
        c.execute('INSERT INTO account(id,username,role,mid,salt,verifier) VALUES(?,?,?,?,?,?)',
                  (aid,name,role,mid,salt,pwd(password,salt)));return aid
    def add_request(self,c,m,title,details,kind,definitions=None,category=None):
        req(kind in ('question','documents','both')); title=clean(title,150);details=clean(details,8000)
        i=new();n=c.execute('SELECT COALESCE(MAX(ord),0)+1 FROM request WHERE mid=?',(m,)).fetchone()[0]
        req(n<=250,409,'request_limit');c.execute('INSERT INTO request VALUES(?,?,?,?,?)',
            (i,m,n,kind,self.protect(m,'request:'+i,{'title':title,'details':details,'category':request_category(kind,title,category),'definitions':request_definitions(definitions if definitions is not None else [])})));return i
    def revoke(self,c,aid):
        c.execute('UPDATE account SET active=0,epoch=epoch+1 WHERE id=? AND role=?',(aid,'client'))
        c.execute('DELETE FROM session WHERE aid=?',(aid,))
    def audit(self,c,m,user,event,item):
        c.execute('INSERT INTO audit(mid,aid,event,item,created) VALUES(?,?,?,?,?)',(m,user['id'],event,item,int(time.time())))

    def reply(self,start,n,body,typ='application/json; charset=utf-8',more=()):
        h=list(HEAD.items())+[('Content-Type',typ),('Content-Length',str(len(body))),*more];start(f'{n} {STATUS[n]}',h);return [body]
    def bytes(self,e,cap,mime):
        req(e.get('CONTENT_TYPE','').split(';',1)[0].lower()==mime,415,'wrong_content_type')
        n=e.get('CONTENT_LENGTH','');req(isinstance(n,str) and re.fullmatch(r'[0-9]{1,8}',n),400,'length_required')
        size=int(n); req(0<size<=cap,413,'file_or_request_too_large')
        raw=e['wsgi.input'].read(size);req(len(raw)==size)
        return raw
    def payload(self,e): return json.loads(self.bytes(e,196608,'application/json'),object_pairs_hook=pairs,
        parse_constant=lambda s: (_ for _ in ()).throw(ValueError()))
    def session_cookie_name(self):
        return AZURE_COOKIE if self.exact_cookie_domain else COOKIE
    def session_cookie(self,token,lifetime):
        domain='; Domain='+self.host if self.session_cookie_name()!=COOKIE else ''
        return f'{self.session_cookie_name()}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={lifetime}'+domain
    def session(self,e,c):
        jar=SimpleCookie()
        try:jar.load(e.get('HTTP_COOKIE',''))
        except CookieError:raise HTTPError(401,'sign_in_required') from None
        name=self.session_cookie_name();t=jar[name].value if name in jar else ''
        req(TOKEN.fullmatch(t),401,'sign_in_required')
        return self.session_hash(c,digest(t))
    def session_hash(self,c,t):
        a=c.execute('SELECT a.*,s.csrf,s.csrf_box FROM session s JOIN account a ON a.id=s.aid WHERE s.token=? AND s.epoch=a.epoch AND s.until>? AND a.active=1',
           (t,int(time.time()))).fetchone()
        req(a is not None,401,'sign_in_required')
        return a,t
    def csrf(self,e,user):
        t=e.get('HTTP_X_CSRF_TOKEN','');req(TOKEN.fullmatch(t) and hmac.compare_digest(digest(t),user['csrf']),403,'refresh_and_try_again')
    def matter(self,c,u,m):
        req(ID.fullmatch(m) and (u['role']=='counsel' or u['mid']==m),404,'not_found')
        q=c.execute('SELECT label FROM matter WHERE id=?',(m,)).fetchone();req(q is not None,404,'not_found')
        return self.read(m,'matter',q['label'])
    def restricted(self,c,m):
        return c.execute('SELECT 1 FROM discovery_access WHERE mid=?',(m,)).fetchone() is not None
    def row(self,c,m,r,u=None):
        q=c.execute('SELECT * FROM request WHERE id=? AND mid=?',(r,m)).fetchone()
        req(q is not None,404,'not_found')
        if u is not None and u['role']=='client' and self.restricted(c,m):
            req(c.execute('SELECT 1 FROM assignment WHERE rid=? AND aid=?',(r,u['id'])).fetchone() is not None,404,'not_found')
            req(c.execute('SELECT 1 FROM client_hidden WHERE rid=?',(r,)).fetchone() is None,404,'not_found')
        return q
    def scope_sql(self,c,u,m,column):
        if u['role']=='client' and self.restricted(c,m):
            return (' AND '+column+' IN (SELECT h.rid FROM assignment h LEFT JOIN client_hidden gone ON gone.rid=h.rid WHERE h.aid=? AND gone.rid IS NULL)', (u['id'],))
        return '', ()
    def assign(self,c,m,r,aid):
        req(isinstance(aid,str) and ID.fullmatch(aid),404,'not_found')
        person=c.execute("SELECT id FROM account WHERE id=? AND mid=? AND role='client' AND active=1",(aid,m)).fetchone()
        req(person is not None and self.restricted(c,m),404,'not_found')
        q=self.row(c,m,r)
        parent=c.execute('SELECT root FROM assignment WHERE rid=?',(r,)).fetchone()
        root=parent['root'] if parent else r
        req(c.execute('SELECT 1 FROM assignment WHERE root=? AND aid=?',(root,aid)).fetchone() is None,409,'already_assigned')
        item=self.read(m,'request:'+r,q['data'])
        new_id=self.add_request(c,m,item['title'],item['details'],q['kind'],item.get('definitions',[]),item.get('category'))
        c.execute('INSERT INTO assignment VALUES(?,?,?)',(new_id,root,aid))
        return new_id
    def intake_open(self,c,r):
        status=c.execute('SELECT status FROM request_review WHERE rid=?',(r,)).fetchone()
        req(not status or status['status']=='needs-more',409,'request_not_accepting_input')
    def rate(self,c,tag,s,limit):
        now=int(time.time());slot=now//s*s
        n=c.execute('SELECT count FROM rate WHERE tag=? AND slot=?',(tag,slot)).fetchone()
        if n and n[0]>=limit:return False
        c.execute('INSERT INTO rate VALUES(?,?,1) ON CONFLICT(slot,tag) DO UPDATE SET count=count+1',(slot,tag));c.execute('DELETE FROM rate WHERE slot<?',(now-86400,))
        return True
    def login(self,e,b):
        exact(b,'username','password');name=b['username'];p=b['password']
        req(isinstance(name,str) and USER.fullmatch(name.lower()) and validpass(p),401,'invalid_sign_in')
        with self.tx(True) as c:
            ok_g=self.rate(c,self.index(b'login-all'),300,60)
            ok_ip=self.rate(c,self.index(b'login-ip:'+str(e.get('REMOTE_ADDR',''))[:96].encode()),300,18) if ok_g else False
            ok_u=self.rate(c,self.index(b'login-user:'+name.lower().encode()),300,6) if ok_ip else False
            user=c.execute('SELECT * FROM account WHERE username=?',(name.lower(),)).fetchone()
        req(ok_u,429,'try_again_later');actual=pwd(p,user['salt'] if user else self.dummy_salt)
        target=user['verifier'] if user else b'\0'*32
        req(hmac.compare_digest(actual,target) and user is not None and user['active'],401,'invalid_sign_in')
        token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32);now=int(time.time())
        with self.tx(True) as c:
            check=c.execute('SELECT epoch,active FROM account WHERE id=?',(user['id'],)).fetchone()
            req(check['active'] and check['epoch']==user['epoch'],401,'invalid_sign_in')
            c.execute('DELETE FROM session WHERE until<=? OR aid=?',(now,user['id']))
            c.execute('INSERT INTO session VALUES(?,?,?,?,?,?)',(digest(token),user['id'],digest(csrf),
                self.box(user['id'],'csrf:'+digest(token).hex(),csrf.encode()),user['epoch'],now+28800))
        return [user['role'],self.session_cookie(token,28800)]

    def upload(self,e,m,r):
        with self.tx(True) as c:
            u,t=self.session(e,c);self.csrf(e,u);self.matter(c,u,m);q=self.row(c,m,r,u)
            req(u['role']=='client',403,'not_permitted')
            req(may_attach(q['kind'],self.read(m,'request:'+r,q['data']),self.restricted(c,m)),409,'not_a_document_request');self.intake_open(c,r)
            req(self.rate(c,self.index(b'upload:'+u['id'].encode()),300,15),429,'try_again_later')
        try:n,ext=filename(e.get('HTTP_X_FILE_NAME',''))
        except (UnicodeError, ValueError) as ex:raise HTTPError(415,str(ex) if isinstance(ex,Rejected) else 'invalid_filename') from None
        req(self.scan_slots.acquire(False),503,'scanner_busy')
        try:
            raw=self.bytes(e,MAX_BYTES,'application/octet-stream')
            try:sha=screened(raw,ext,self.scanner)
            except Rejected as ex:raise HTTPError(415,str(ex)) from None
            except ScannerOffline:raise HTTPError(503,'scanner_unavailable') from None
        finally:self.scan_slots.release()
        k=self.index(dump(['original',m,r,sha]));now=int(time.time())
        with self.tx(True) as c:
            u2,_=self.session_hash(c,t);self.matter(c,u2,m);self.row(c,m,r,u2);self.intake_open(c,r)
            prior=c.execute('SELECT id FROM file WHERE mid=? AND rid=? AND dedup=?',(m,r,k)).fetchone()
            if prior:return 200,{'fileId':prior['id'],'status':'already_received'}
            cap=c.execute('SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM file WHERE mid=?',(m,)).fetchone()
            req(cap[0]<FILE_CAP and cap[1]+len(raw)<=MATTER_BYTES,413,'matter_upload_limit')
            i=new();meta={'name':n,'mediaType':ALLOWED[ext],'sha256':sha,'screening':'scanner_and_type_checks_passed'}
            c.execute('INSERT INTO file VALUES(?,?,?,?,?,?,?,?,?)',(i,m,r,u2['id'],len(raw),k,self.protect(m,'file-meta:'+i,meta),self.box(m,'file-bytes:'+i,raw),now))
            self.audit(c,m,u2,'file_received',i)
            return 201,{'fileId':i,'status':'received','sha256':sha}

    def original(self,m,f,meta):
        return self.open(m,'file-bytes:'+f['id'],f['data'])

    def visible_file(self,c,u,fid):
        return True

    def matter_payload(self,c,u,m,label):
        counsel=u['role']=='counsel'
        requests=[]
        files={}
        filt,args=self.scope_sql(c,u,m,'f.rid')
        for a in c.execute('SELECT f.id,f.rid,f.meta,f.bytes,f.created,fr.status,fr.notes FROM file f LEFT JOIN file_review fr ON fr.fid=f.id WHERE f.mid=?'+filt+' ORDER BY f.created,f.id',(m,*args)).fetchall():
            if not self.visible_file(c,u,a['id']):continue
            x=self.read(m,'file-meta:'+a['id'],a['meta']);x.update(fileId=a['id'],size=a['bytes'],receivedAt=a['created'])
            if counsel:x.update(status=a['status'] or 'unreviewed',reviewNote=self.read(m,'file-review:'+a['id'],a['notes']) if a['notes'] else '')
            else:x={'name':x['name'],'size':x['size'],'fileId':x['fileId'],'receivedAt':x['receivedAt']}
            files.setdefault(a['rid'],[]).append(x)
        filt,args=self.scope_sql(c,u,m,'r.id')
        rows=c.execute('SELECT r.*,a.data AS response,b.created AS submitted,rr.status,rr.notes,f.data AS followup, ass.root, ass.aid, au.username FROM request r LEFT JOIN answer a ON a.rid=r.id LEFT JOIN batch b ON b.id=a.bid LEFT JOIN request_review rr ON rr.rid=r.id LEFT JOIN followup f ON f.rid=r.id LEFT JOIN assignment ass ON ass.rid=r.id LEFT JOIN account au ON au.id=ass.aid WHERE r.mid=?'+filt+' ORDER BY r.ord',(m,*args)).fetchall()
        for q in rows:
            i=q['id']; item=self.read(m,'request:'+i,q['data'])
            item.update(id=i,number=q['ord'],kind=q['kind'],category=request_category(q['kind'],item['title'],item.get('category')),status=q['status'] or 'open',files=files.get(i,[]))
            if q['response']:item['response']=self.read(m,'answer:'+i,q['response']);item['submittedAt']=q['submitted']
            if not counsel and not q['response']:
                draft=c.execute('SELECT data FROM draft WHERE aid=? AND rid=?',(u['id'],i)).fetchone()
                if draft:item['draft']=self.read(m,'draft:'+u['id']+':'+i,draft[0])
            if q['kind']=='documents':
                updates=[]
                for v in c.execute('SELECT * FROM production_update WHERE rid=? ORDER BY created,rowid',(i,)).fetchall():
                    z={'id':v['id'],'kind':v['kind'],'text':self.read(m,'production-update:'+v['id'],v['data']),'at':v['created']}
                    if v['reply']:z['reply']=self.read(m,'production-reply:'+v['id'],v['reply'])
                    updates.append(z)
                if updates:item['productionUpdates']=updates
            if q['followup']:item['followUp']=self.read(m,'followup:'+i,q['followup'])
            if counsel:
                item['reviewNote']=self.read(m,'request-review:'+i,q['notes']) if q['notes'] else ''
                item['clientHidden']=c.execute('SELECT 1 FROM client_hidden WHERE rid=?',(i,)).fetchone() is not None
                item['rootRequestId']=q['root'] or i
                item['respondent']=q['username'] or None
                item['respondentId']=q['aid'] or None
            requests.append(item)
        result={'id':m,'title':label,'requests':requests,'batchSize':10,'assignmentsEnabled':self.restricted(c,m)}
        if counsel:
            result['respondents']=[dict(a) for a in c.execute("SELECT id,username,active FROM account WHERE mid=? AND role='client' ORDER BY username",(m,))]
            result['assignmentsEnabled']=self.restricted(c,m)
        return result

    def activity(self,c,m):
        """A counsel-only matter timeline. No file names, notes, or response text."""
        out=[]
        rows=c.execute("""SELECT a.seq,a.event,a.created,
               COALESCE(f.rid,r.id) AS request_id, b.id AS batch_id
               FROM audit a
               LEFT JOIN file f ON a.event IN ('file_received','file_reviewed') AND f.id=a.item AND f.mid=a.mid
               LEFT JOIN request r ON a.event IN ('request_added','follow-up','review','document_progress','document_help_reply','document_status','request_hidden','request_reopened') AND r.id=a.item AND r.mid=a.mid
               LEFT JOIN batch b ON a.event='batch_submitted' AND b.id=a.item AND b.mid=a.mid
               WHERE a.mid=? ORDER BY a.seq DESC LIMIT 41""",(m,)).fetchall()
        for a in rows[:40]:
            if a['event'] in VISIBLE_ACTIVITY:
                x={'event':a['event'],'at':a['created']}
                if a['request_id']:x['requestId']=a['request_id']
                if a['batch_id']:x['count']=c.execute('SELECT COUNT(*) FROM answer WHERE bid=?',(a['batch_id'],)).fetchone()[0]
                out.append(x)
        return {'entries':out,'more':len(rows)>40}

    def submit(self,c,u,m,b):
        exact(b,'responses'); entries=b['responses'];req(type(entries) is list and 1<=len(entries)<=10)
        ids=set();values=[]
        filt,args=self.scope_sql(c,u,m,'r.id')
        is_discovery=self.restricted(c,m)
        if is_discovery:filt+=" AND r.kind!='documents'"
        available=[x[0] for x in c.execute('SELECT r.id FROM request r LEFT JOIN answer a ON a.rid=r.id LEFT JOIN request_review rr ON rr.rid=r.id WHERE r.mid=? AND a.rid IS NULL AND COALESCE(rr.status,\'open\') NOT IN (\'complete\',\'held\')'+filt+' ORDER BY r.ord'+('' if is_discovery else ' LIMIT 10'),(m,*args))]
        for ent in entries:
            exact(ent,'id','kind','text');i=ent['id'];k=ent['kind'];req(type(i) is str and ID.fullmatch(i) and i not in ids and k in RESPONSES|{'uploaded'})
            q=self.row(c,m,i,u);text=clean(ent['text'],5000,k not in {'answer','partial_input'}|DOCUMENT_STATEMENTS)
            if k in DOCUMENT_STATEMENTS: req(q['kind'] in ('documents','both'))
            if is_discovery:req(q['kind']!='documents',409,'use_document_page')
            if k in FACT_CHOICES:
                item=self.read(m,'request:'+i,q['data'])
                req(q['kind']=='question' and request_category(q['kind'],item['title'],item.get('category'))=='rfa')
            if k=='uploaded':
                req(q['kind']=='documents' and any(self.visible_file(c,u,f[0]) for f in c.execute('SELECT id FROM file WHERE mid=? AND rid=?',(m,i)).fetchall()),409,'upload_required')
            ids.add(i);values.append((i,k,text))
        # Recover an exact retry after a lost network reply without another submission.
        existing=[]
        for i,k,t in values:
            a=c.execute('SELECT a.bid,a.data,b.aid FROM answer a JOIN batch b ON b.id=a.bid WHERE a.rid=? AND b.mid=?',(i,m)).fetchone()
            if a:existing.append((a['bid'],a['aid']==u['id'] and self.read(m,'answer:'+i,a['data'])=={'kind':k,'text':t}))
        if existing:
            bid=existing[0][0]
            match=len(existing)==len(values) and all(i==bid and ok for i,ok in existing)
            req(match and c.execute('SELECT COUNT(*) FROM answer WHERE bid=?',(bid,)).fetchone()[0]==len(values),409,'request_already_submitted_or_outside_batch')
            return 200,{'receipt':bid,'count':len(values),'status':'already_received'}
        req(ids.issubset(set(available)) if is_discovery else ids==set(available),409,'batch_changed')
        bid=new();now=int(time.time());c.execute('INSERT INTO batch VALUES(?,?,?,?)',(bid,m,u['id'],now))
        for i,k,t in values:
            c.execute('INSERT INTO answer VALUES(?,?,?)',(i,bid,self.protect(m,'answer:'+i,{'kind':k,'text':t})))
            c.execute('DELETE FROM draft WHERE aid=? AND rid=?',(u['id'],i))
        self.audit(c,m,u,'batch_submitted',bid)
        return 201,{'receipt':bid,'count':len(values),'status':'received'}

    def api(self,e,meth,path,start):
        if path=='/api/sign-in' and meth=='POST':
            role,ck=self.login(e,self.payload(e));return self.reply(start,200,dump({'role':role}),more=(('Set-Cookie',ck),))
        mt=re.fullmatch(r'/api/matters/([0-9a-f]{32})(/.*)?',path)
        if mt:
            m=mt[1]; sub=mt[2] or ''
            up=re.fullmatch(r'/requests/([0-9a-f]{32})/files',sub)
            if up and meth=='POST':
                n,x=self.upload(e,m,up[1]);return self.reply(start,n,dump(x))
        with self.tx(meth!='GET') as c:
            u,t=self.session(e,c)
            if meth!='GET': self.csrf(e,u)
            if path=='/api/session' and meth=='GET':
                csrf=self.open(u['id'],'csrf:'+t.hex(),u['csrf_box']).decode()
                return self.reply(start,200,dump({'role':u['role'],'csrf':csrf,'matterId':u['mid']}))
            if path=='/api/sign-out' and meth=='POST':
                c.execute('DELETE FROM session WHERE token=?',(t,))
                return self.reply(start,200,b'{}',more=(('Set-Cookie',self.session_cookie('',0)),))
            if path=='/api/matters' and meth=='GET':
                items=c.execute('SELECT * FROM matter ORDER BY id' if u['role']=='counsel' else 'SELECT * FROM matter WHERE id=?',() if u['role']=='counsel' else (u['mid'],))
                return self.reply(start,200,dump([{'id':a['id'],'title':self.read(a['id'],'matter',a['label'])} for a in items]))
            if path=='/api/matters' and meth=='POST':
                req(u['role']=='counsel',403,'not_permitted')
                return self.reply(start,201,dump(self.provision(c,u,self.payload(e))))
            req(mt is not None,404,'not_found')
            label=self.matter(c,u,m)
            if not sub and meth=='GET': return self.reply(start,200,dump(self.matter_payload(c,u,m,label)))
            if sub=='/submit' and meth=='POST':
                req(u['role']=='client',403,'not_permitted'); n,x=self.submit(c,u,m,self.payload(e));return self.reply(start,n,dump(x))
            production=re.fullmatch(r'/requests/([0-9a-f]{32})/production-status',sub)
            if production and meth=='POST':
                req(u['role']=='client' and self.restricted(c,m),403,'not_permitted')
                i=production[1]; q=self.row(c,m,i,u); self.intake_open(c,i)
                req(q['kind']=='documents',409,'not_a_document_request')
                b=self.payload(e); exact(b,'kind','text')
                kind=b['kind']; req(isinstance(kind,str) and kind in DOCUMENT_STATEMENTS|DOCUMENT_PROGRESS|{'uploaded','clarification','unknown','answer'})
                val=clean(b['text'],5000,kind not in DOCUMENT_STATEMENTS|{'answer','help'})
                if kind in DOCUMENT_PROGRESS:
                    prev=c.execute('SELECT * FROM production_update WHERE rid=? AND aid=? ORDER BY created DESC,rowid DESC LIMIT 1',(i,u['id'])).fetchone()
                    if prev and not prev['reply'] and prev['kind']==kind and self.read(m,'production-update:'+prev['id'],prev['data'])==val:
                        return self.reply(start,200,b'{}')
                    req(c.execute('SELECT COUNT(*) FROM production_update WHERE rid=?',(i,)).fetchone()[0]<50,409,'request_limit')
                    v=new()
                    c.execute('INSERT INTO production_update VALUES(?,?,?,?,?,?,NULL)',(v,i,u['id'],kind,self.protect(m,'production-update:'+v,val),int(time.time())))
                    self.audit(c,m,u,'document_progress',i)
                    return self.reply(start,201,b'{}')
                if kind=='uploaded':
                    req(any(self.visible_file(c,u,f[0]) for f in c.execute('SELECT id FROM file WHERE mid=? AND rid=?',(m,i)).fetchall()),409,'upload_required')
                before=c.execute('SELECT data FROM answer WHERE rid=?',(i,)).fetchone()
                if before:
                    if self.read(m,'answer:'+i,before[0])=={'kind':kind,'text':val}:
                        return self.reply(start,200,b'{}')
                    raise HTTPError(409,'already_submitted')
                bid=new();c.execute('INSERT INTO batch VALUES(?,?,?,?)',(bid,m,u['id'],int(time.time())))
                c.execute('INSERT INTO answer VALUES(?,?,?)',(i,bid,self.protect(m,'answer:'+i,{'kind':kind,'text':val})))
                self.audit(c,m,u,'document_status',i)
                return self.reply(start,201,b'{}')
            draft=re.fullmatch(r'/requests/([0-9a-f]{32})/draft',sub)
            if draft and meth=='POST':
                req(u['role']=='client',403,'not_permitted');i=draft[1]
                q=self.row(c,m,i,u);self.intake_open(c,i)
                req(c.execute('SELECT 1 FROM answer WHERE rid=?',(i,)).fetchone() is None,409,'already_submitted')
                b=self.payload(e);exact(b,'kind','text')
                req(b['kind'] in RESPONSES|{'uploaded',''})
                if b['kind'] in DOCUMENT_STATEMENTS: req(q['kind'] in ('documents','both'))
                if b['kind'] in FACT_CHOICES:
                    q=self.row(c,m,i); item=self.read(m,'request:'+i,q['data'])
                    req(q['kind']=='question' and request_category(q['kind'],item['title'],item.get('category'))=='rfa')
                v=clean(b['text'],5000,True)
                c.execute('INSERT INTO draft VALUES(?,?,?) ON CONFLICT(aid,rid) DO UPDATE SET data=excluded.data',
                    (u['id'],i,self.protect(m,'draft:'+u['id']+':'+i,{'kind':b['kind'],'text':v})))
                return self.reply(start,200,b'{}')
            req(u['role']=='counsel',403,'not_permitted')
            if sub=='/activity' and meth=='GET':
                return self.reply(start,200,dump(self.activity(c,m)))
            if sub=='/report' and meth=='GET':
                payload=self.matter_payload(c,u,m,label);payload['audit']=[dict(a) for a in c.execute('SELECT event,item,created FROM audit WHERE mid=? ORDER BY seq',(m,))]
                return self.reply(start,200,dump(payload),more=(('Content-Disposition','attachment; filename="intake-report.json"'),))
            dl=re.fullmatch(r'/files/([0-9a-f]{32})(/review)?',sub)
            if dl:
                i=dl[1];f=c.execute('SELECT * FROM file WHERE id=? AND mid=?',(i,m)).fetchone();req(f is not None and self.visible_file(c,u,i),404,'not_found')
                if dl[2] and meth=='POST':
                    b=self.payload(e);exact(b,'status','note');req(b['status'] in ('accepted','needs-more','held'))
                    c.execute('INSERT INTO file_review VALUES(?,?,?) ON CONFLICT(fid) DO UPDATE SET status=excluded.status,notes=excluded.notes',
                        (i,b['status'],self.protect(m,'file-review:'+i,clean(b['note'],2000,True))))
                    self.audit(c,m,u,'file_reviewed',i);return self.reply(start,200,b'{}')
                if not dl[2] and meth=='GET':
                    meta=self.read(m,'file-meta:'+i,f['meta']);raw=self.original(m,f,meta)
                    req(len(raw)==f['bytes'] and hmac.compare_digest(hashlib.sha256(raw).hexdigest(),meta['sha256']),503,'integrity_check_failed')
                    return self.reply(start,200,raw,'application/octet-stream',
                        (('Content-Disposition',"attachment; filename*=UTF-8''"+quote(meta['name'],safe='')),))
            help_reply=re.fullmatch(r'/requests/([0-9a-f]{32})/production-help/([0-9a-f]{32})',sub)
            if help_reply and meth=='POST':
                i,v=help_reply.groups()
                self.row(c,m,i)
                b=self.payload(e);exact(b,'text');val=clean(b['text'],5000)
                previous=c.execute("SELECT reply FROM production_update WHERE id=? AND rid=? AND kind='help'",(v,i)).fetchone()
                req(previous is not None,404,'not_found')
                if previous['reply']:
                    req(self.read(m,'production-reply:'+v,previous['reply'])==val,409,'already_replied')
                    return self.reply(start,200,b'{}')
                c.execute('UPDATE production_update SET reply=? WHERE id=?',(self.protect(m,'production-reply:'+v,val),v))
                self.audit(c,m,u,'document_help_reply',i)
                return self.reply(start,201,b'{}')
            if sub=='/respondents' and meth=='POST':
                req(self.restricted(c,m),409,'assignments_not_enabled')
                b=self.payload(e);exact(b,'username','password')
                name=b['username']
                req(isinstance(name,str) and USER.fullmatch(name) and validpass(b['password']))
                req(c.execute('SELECT 1 FROM account WHERE username=?',(name,)).fetchone() is None,409,'username_unavailable')
                req(c.execute("SELECT COUNT(*) FROM account WHERE mid=? AND role='client'",(m,)).fetchone()[0]<30,409,'respondent_limit')
                aid=self.register(c,name,b['password'],'client',m)
                return self.reply(start,201,dump({'id':aid}))
            revoke=re.fullmatch(r'/respondents/([0-9a-f]{32})/revoke',sub)
            if revoke and meth=='POST':
                req(self.payload(e)=={})
                aid=revoke[1]
                req(c.execute("SELECT 1 FROM account WHERE id=? AND mid=? AND role='client'",(aid,m)).fetchone() is not None,404,'not_found')
                self.revoke(c,aid);self.audit(c,m,u,'client_access_revoked',aid)
                return self.reply(start,200,b'{}')
            assign=re.fullmatch(r'/requests/([0-9a-f]{32})/assignments',sub)
            if assign and meth=='POST':
                b=self.payload(e);exact(b,'respondentId')
                i=self.assign(c,m,assign[1],b['respondentId']);self.audit(c,m,u,'request_added',i)
                return self.reply(start,201,dump({'id':i}))
            if sub=='/requests' and meth=='POST':
                b=self.payload(e); restricted=self.restricted(c,m)
                exact(b,'title','details','kind',*(['respondentId'] if restricted else []),*[key for key in ('category','definitions') if key in b])
                if restricted:
                    person=b['respondentId']
                    req(isinstance(person,str) and ID.fullmatch(person),404,'not_found')
                    req(c.execute("SELECT 1 FROM account WHERE id=? AND mid=? AND role='client' AND active=1",(person,m)).fetchone() is not None,404,'not_found')
                i=self.add_request(c,m,b['title'],b['details'],b['kind'],b.get('definitions',[]),b.get('category'))
                if restricted:c.execute('INSERT INTO assignment VALUES(?,?,?)',(i,i,person))
                self.audit(c,m,u,'request_added',i)
                return self.reply(start,201,dump({'id':i}))
            action=re.fullmatch(r'/requests/([0-9a-f]{32})/(review|follow-up|visibility)',sub)
            if action and meth=='POST':
                i=action[1];self.row(c,m,i);b=self.payload(e)
                if action[2]=='review':
                    exact(b,'status','note');req(b['status'] in ('complete','needs-more','held'));v=clean(b['note'],2000,True)
                    c.execute('INSERT INTO request_review VALUES(?,?,?) ON CONFLICT(rid) DO UPDATE SET status=excluded.status,notes=excluded.notes',(i,b['status'],self.protect(m,'request-review:'+i,v)))
                elif action[2]=='visibility':
                    exact(b,'visible');req(type(b['visible']) is bool and self.restricted(c,m))
                    if not b['visible']:
                        has_answer=c.execute('SELECT 1 FROM answer WHERE rid=?',(i,)).fetchone()
                        status=c.execute('SELECT status FROM request_review WHERE rid=?',(i,)).fetchone()
                        req(has_answer or (status and status['status']=='complete'),409,'unresolved_request')
                        c.execute('INSERT OR IGNORE INTO client_hidden VALUES(?,?)',(i,int(time.time())))
                    else:
                        # Unhide; the evidence, submissions and audit remain intact.
                        c.execute('DELETE FROM client_hidden WHERE rid=?',(i,))
                    self.audit(c,m,u,'request_reopened' if b['visible'] else 'request_hidden',i)
                    return self.reply(start,200,b'{}')
                else:
                    exact(b,'text');v=clean(b['text'],5000);req(c.execute('SELECT 1 FROM answer WHERE rid=?',(i,)).fetchone() is not None,409,'no_submitted_response')
                    # Immutable response history; counsel can add a new request when an answer is needed.
                    req(c.execute('SELECT 1 FROM followup WHERE rid=?',(i,)).fetchone() is None,409,'already_replied')
                    c.execute('INSERT INTO followup VALUES(?,?)',(i,self.protect(m,'followup:'+i,v)))
                self.audit(c,m,u,action[2],i);return self.reply(start,200,b'{}')
        raise HTTPError(404,'not_found')

    def __call__(self,e,start):
        try:
            req(e.get('HTTP_HOST')==self.host,404,'not_found')
            meth=e['REQUEST_METHOD'];path=e['PATH_INFO'];req(meth in ('GET','POST'),404,'not_found')
            if not path.startswith('/api/'):
                a={'/':('index.html','text/html'),'/app.js':('app.js','text/javascript'),'/app.css':('app.css','text/css')}.get(path)
                req(a is not None and meth=='GET',404,'not_found')
                return self.reply(start,200,(ASSETS/a[0]).read_bytes(),a[1]+'; charset=utf-8')
            if meth=='POST': req(e.get('HTTP_ORIGIN')==self.origin and e.get('HTTP_SEC_FETCH_SITE','same-origin')=='same-origin',403,'wrong_origin')
            # Do not emit WSGI success headers until the transaction commits.
            response=[]
            result=self.api(e,meth,path,lambda status,headers:response.extend([status,headers]))
            start(*response)
            return result
        except HTTPError as ex:return self.reply(start,ex.status,dump({'error':ex.code}))
        except (ValueError,TypeError,KeyError,RecursionError):return self.reply(start,400,b'{"error":"invalid_request"}')
        except (sqlite3.Error,InvalidTag):return self.reply(start,503,b'{"error":"storage_unavailable"}')

def configured_key():
    cred=os.environ.get('CREDENTIALS_DIRECTORY')
    env=os.environ.get('INTAKE_V2_KEY')
    if bool(cred)==bool(env):raise ValueError('Choose exactly one v2 encryption-key source')
    val=Path(cred,'intake-key').read_text(encoding='ascii').strip() if cred else env
    if not re.fullmatch(r'[a-fA-F0-9]{64}',val):raise ValueError('Invalid v2 encryption key')
    return bytes.fromhex(val)

def from_environment():
    os.umask(0o077)
    return Portal(os.environ['INTAKE_V2_DB'],configured_key(),os.environ['INTAKE_V2_ORIGIN'],Clamd(os.environ['INTAKE_V2_CLAMD_SOCKET']))
