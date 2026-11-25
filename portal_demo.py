"""Local, invented-data demonstration. There is intentionally no deployable public mode."""
from __future__ import annotations
import hashlib, hmac, html, os, re, secrets, sqlite3, tempfile, time
from email.parser import BytesParser
from email.policy import default as email_policy
from local_scan import LIMIT, verdict
from http.cookies import SimpleCookie, CookieError
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit
from wsgiref.simple_server import WSGIRequestHandler, make_server

LABELS={"still_searching":"I’m still searching","help":"Ask my lawyer for help",
        "not_kept":"We don’t keep that kind of record","never_existed":"I don’t think it ever existed",
        "cannot_find":"I looked and couldn’t find it","answer":"Send my private answer"}
PASS=lambda value,salt: hashlib.scrypt(value.encode(),salt=salt,n=16384,r=8,p=1)
E=lambda value: html.escape(str(value),quote=True)
CSS=b"""body{font:16px system-ui;color:#152434;background:#edf2f6;max-width:780px;margin:2em auto;padding:0 1rem}section{background:#fff;padding:1.1rem;margin:1rem 0;border-radius:.65rem}header{background:#18384c;color:#fff;padding:1rem;border-radius:.65rem}label,p,small{display:block;margin:.5rem 0}input,select,textarea,button{font:inherit;padding:.45rem}textarea{width:min(95%,38em);min-height:5em}a{color:#174b6f}nav{margin-top:.7rem}header a{color:#fff}button{margin:.2rem .3rem .2rem 0}.warn{font-weight:650}pre{white-space:pre-wrap}"""

def point(code,title):
    return str(code)+' '+title

# Verbatim source definitions for the invented request set. Never infer definitions.
DEFINITIONS = {
    "lantern exhibition": ("Definitions ¶ 1", "The display of demonstration lanterns in the observatory on the evening described in these requests.", "The lantern display at the observatory that evening, not another exhibit or another night."),
    "checkout sheet": ("Definitions ¶ 2", "The paper or electronic list used to record each lantern removed from or returned to the observatory.", "The paper or digital log that records lanterns taken out or brought back. Either format counts."),
}
TERM_PATTERN = re.compile(r"(?<!\w)(?:" + "|".join(re.escape(term) for term in sorted(DEFINITIONS,key=len,reverse=True)) + r")(?!\w)",re.I)
VIEWS = {"/interrogatories":"Interrogatories (ROGs)","/documents":"Requests for Production (RPDs)","/admissions":"Requests for Admission (RFAs)"}

def marked_question(original):
    out=[]; used=[]; pos=0
    for m in TERM_PATTERN.finditer(original):
        term=m.group().casefold()
        out.extend((E(original[pos:m.start()]),"<mark>"+E(m.group())+"</mark>"))
        if term not in used:used.append(term)
        pos=m.end()
    out.append(E(original[pos:]))
    definition_box=""
    if used:
        definition_box="<details open><summary>Defined terms and what they mean</summary><dl>"+ "".join(
            "<dt><strong>"+E(t)+"</strong> <small>"+E(DEFINITIONS[t][0])+"</small></dt><dd><p><strong>Exact definition from the request:</strong> "+E(DEFINITIONS[t][1])+"</p><p><strong>In plain English:</strong> "+E(DEFINITIONS[t][2])+"</p></dd>" for t in used
        )+"</dl></details>"
    return "".join(out),definition_box

def is_interrogatory(request):
    return request["kind"] == "question" and request["ref"].startswith("Interrogatory ")

def request_view(request):
    if request["kind"] == "document": return "/documents"
    if is_interrogatory(request): return "/interrogatories"
    return "/admissions"

def request_anchor(request):
    return request_view(request) + "#request-" + request["id"]

class Demo:
    def __init__(self,directory,port,scanner_socket=None):
        self.port=port; self.origin=f"http://127.0.0.1:{port}"
        self.db=Path(directory)/"demo.sqlite3";self.scanner_socket=scanner_socket
        self.passwords={name:secrets.token_urlsafe(18) for name in ("counsel","witness","records")}
        with sqlite3.connect(self.db) as db:
            db.executescript("""
                CREATE TABLE person(name TEXT PRIMARY KEY,salt BLOB,digest BLOB);
                CREATE TABLE session(token BLOB PRIMARY KEY,name TEXT,csrf TEXT,until INTEGER);
                CREATE TABLE request(id TEXT PRIMARY KEY,ref TEXT,kind TEXT,recipient TEXT,title TEXT,hidden INTEGER DEFAULT 0);
                CREATE TABLE upload(id TEXT PRIMARY KEY,req TEXT NOT NULL,name TEXT NOT NULL,sha TEXT NOT NULL,bytes BLOB NOT NULL,status TEXT NOT NULL);
                CREATE TABLE event(id INTEGER PRIMARY KEY,request_id TEXT,actor TEXT,kind TEXT,notes TEXT,when_utc INTEGER);
            """)
            for n,pw in self.passwords.items():
                salt=secrets.token_bytes(16)
                db.execute("INSERT INTO person VALUES(?,?,?)",(n,salt,PASS(pw,salt)))
            for ref,kind,who,title in [
                ("Interrogatory 1","question","witness","Who unlocked the fictional observatory on the night of the lantern exhibition?"),
                ("Admission 1","question","witness","Was a blue lantern present when the exhibition opened? Explain what you personally saw."),
                ("Production 1","document","records","Locate the observatory’s lantern checkout sheet."),
                ("Production 2","document","records","Look for a copy of the fictional exhibit setup instructions."),
                ("Production 1","document","witness","Do you have an individual copy of the lantern checkout sheet?"),
            ]:
                db.execute("INSERT INTO request(id,ref,kind,recipient,title) VALUES(?,?,?,?,?)",(secrets.token_hex(10),ref,kind,who,title))
        self.fake_salt=secrets.token_bytes(16)

    def page(self,content,person=None,csrf=None):
        logout=("<form method='post' action='/logout'><input type='hidden' name='csrf' value='"+E(csrf)+"'><button>Sign out</button></form>") if person else ""
        who=("<p>Signed in as <b>"+E(person)+"</b></p>") if person else ""
        s=("<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Discovery Portal: Local Demo</title><link rel='stylesheet' href='/style.css'>"
            "<header><strong>Discovery Portal</strong><p>Local demo · invented materials only</p></header>"+who+logout+content+"</html>")
        return s.encode()

    def reply(self,start,code,content=b"",ctype="text/html; charset=utf-8",more=()):
        start(code,[("Content-Type",ctype),("Content-Length",str(len(content))),("Cache-Control","no-store"),
                   ("X-Content-Type-Options","nosniff"),("Referrer-Policy","same-origin"),
                   ("Content-Security-Policy","default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),*more])
        return [content]

    def decode(self,env):
        if env.get("CONTENT_TYPE","").split(";")[0]!="application/x-www-form-urlencoded":raise ValueError()
        raw_len=env.get("CONTENT_LENGTH","")
        if not raw_len.isascii() or not raw_len.isdecimal():raise ValueError()
        n=int(raw_len)
        if not 1<=n<=24576:raise ValueError()
        raw=env["wsgi.input"].read(n)
        if len(raw)!=n:raise ValueError()
        vals=parse_qs(raw.decode("utf8"),keep_blank_values=True,max_num_fields=12,strict_parsing=True)
        if any(len(v)!=1 for v in vals.values()):raise ValueError()
        return {k:v[0] for k,v in vals.items()}

    def multipart(self,env):
        mime=env.get('CONTENT_TYPE','')
        if not mime.isascii() or not mime.startswith('multipart/form-data;') or len(mime)>200 or any(c in mime for c in '\r\n'):raise ValueError()
        length=env.get('CONTENT_LENGTH','')
        if not length.isascii() or not length.isdecimal() or len(length)>8:raise ValueError()
        size=int(length)
        if not 0<size<=LIMIT+8192:raise ValueError('That file exceeds the 2 MiB demo limit.')
        raw=env['wsgi.input'].read(size)
        if len(raw)!=size:raise ValueError()
        msg=BytesParser(policy=email_policy).parsebytes(b'Content-Type: '+mime.encode('ascii')+b'\r\nMIME-Version: 1.0\r\n\r\n'+raw)
        if not msg.is_multipart() or msg.defects:raise ValueError()
        parts={}
        for part in msg.iter_parts():
            k=part.get_param('name',header='Content-Disposition')
            if k not in {'csrf','file'} or k in parts or part.is_multipart() or part.defects or part.get('Content-Transfer-Encoding'):raise ValueError()
            parts[k]=(part.get_filename(),part.get_payload(decode=True))
        csrf=parts['csrf'][1].decode('ascii')
        name,blob=parts['file']
        if not name or not blob:raise ValueError("Choose a nonempty PDF or text file.")
        try: name=name.encode("ascii","surrogateescape").decode("utf-8")
        except (UnicodeEncodeError,UnicodeDecodeError):pass
        if len(name)>180 or any(ord(c)<32 or ord(c)==127 or c in '/\\:' or 0xD800<=ord(c)<=0xDFFF for c in name):
            raise ValueError("The filename is too long or contains a character this demo cannot accept.")
        if not name.lower().endswith((".pdf",".txt")):
            raise ValueError("This demo accepts PDF and text (.txt) files only.")
        if len(blob)>LIMIT:raise ValueError("That file exceeds the 2 MiB demo limit.")
        if name.lower().endswith('.pdf'):
            if not blob.startswith(b'%PDF-') or not blob.rstrip().endswith(b'%%EOF'):raise ValueError('The selected file does not appear to be a complete PDF.')
        else:
            txt=blob.decode('utf-8')
            if any(ord(x)<32 and x not in '\t\n\r' for x in txt):raise ValueError()
        return csrf,name,blob

    def view(self,db,person,csrf,page="/"):
        if person=="counsel": rows=db.execute("SELECT * FROM request ORDER BY ref,recipient").fetchall()
        else: rows=db.execute("SELECT * FROM request WHERE recipient=? AND hidden=0 ORDER BY ref,id",(person,)).fetchall()
        counters={path:sum(request_view(r)==path for r in rows) for path in VIEWS}
        nav="<nav aria-label='Discovery groups'><a href='/'>Overview</a> · "+" · ".join(
            "<a href='"+path+"'"+(" aria-current='page'" if page==path else "")+">"+E(label)+" ("+str(counters[path])+")</a>"
            for path,label in VIEWS.items())+"</nav>"
        header="<p class='warn'>For your lawyer only. This local demonstration is not a final discovery response. Do not enter actual case information.</p>"
        parts=[nav,header]
        if page!="/":
            rows=[r for r in rows if request_view(r)==page]
            parts.append("<h1>"+E(VIEWS[page])+"</h1>")
            if not rows:parts.append("<p>No requests of this type are assigned to you.</p>")
        else:
            parts.append("<h1>All assignments</h1><p>Open any section and work in any order. You can skip a request and return later.</p>")
        for r in rows:
            wording,definitions=marked_question(r["title"])
            parts.append("<section id='request-"+E(r["id"])+"'><h2>"+E(r["ref"])+"</h2><p>"+wording+"</p>"+definitions)
            hist=db.execute("SELECT * FROM event WHERE request_id=? ORDER BY id",(r["id"],)).fetchall()
            if person=="counsel":
                parts.append("<small>Assigned to "+E(r["recipient"])+(" · hidden" if r["hidden"] else "")+"</small>")
            for h in hist:
                parts.append("<p><small>"+E(h["actor"])+" · "+E(LABELS.get(h["kind"],h["kind"]))+"</small>"+E(h["notes"])+"</p>")
            csrf_input="<input type='hidden' name='csrf' value='"+E(csrf)+"'>"
            for f in db.execute("SELECT id,name,status FROM upload WHERE req=? ORDER BY rowid",(r["id"],)):
                label=E(f['name'])+" · "+E(f["status"])
                if person=="counsel" and f['status']=='clean':
                    parts.append("<p>"+label+" · <a href='/download/"+E(f["id"])+"'>Download original</a></p>")
                elif person=="counsel" and f['status']=='pending':
                    parts.append("<form method='post' action='/scan/"+E(f["id"])+"'>"+csrf_input+"<p>"+label+"</p><button>Check with local scanner</button></form>")
                else:parts.append("<p>"+label+"</p>")
            if person=="counsel":
                parts.append("<form method='post' action='/reply/"+E(r["id"])+"'>"+csrf_input+
                  "<label>Private reply<textarea name='notes' maxlength='3500' required></textarea></label><button>Post reply</button></form>")
                if hist:
                    parts.append("<form method='post' action='/visibility/"+E(r["id"])+"'>"+csrf_input+
                        "<button>"+("Show to respondent" if r["hidden"] else "Hide from respondent (keep record)")+"</button></form>")
            else:
                kinds=("still_searching","help","not_kept","never_existed","cannot_find") if r["kind"]=="document" else ("answer","help")
                choices="".join("<button name='kind' value='"+k+"'>"+E(LABELS[k])+"</button>" for k in kinds)
                parts.append("<form method='post' action='/respond/"+E(r["id"])+"'>"+csrf_input+
                  "<label>Private note<textarea name='notes' maxlength='3500'></textarea></label>"+choices+"</form>")
                if r["kind"]=="document" or is_interrogatory(r):
                    rog=is_interrogatory(r)
                    parts.append("<form method='post' enctype='multipart/form-data' action='/upload/"+E(r["id"])+"'>"+csrf_input+
                        ("<p><strong>Supporting documents (optional)</strong><br>You can answer and attach files in either order. No file is required. Save any text you have typed before attaching a file.</p>" if rog else "")+
                        "<label>Invented file (PDF or text; 2 MiB maximum)<input type='file' name='file' accept='.pdf,.txt' required></label>"+
                        ("<button>Attach supporting file</button>" if rog else "<button>Upload to quarantine</button>")+
                        "</form><p><small>Repeat for more files. Nothing can be downloaded until the independent scanner clears it.</small></p>")
            parts.append("</section>")
        return self.page("".join(parts),person,csrf)

    def __call__(self,env,start):
        if (env.get("REMOTE_ADDR")!="127.0.0.1" or env.get("HTTP_HOST")!=f"127.0.0.1:{self.port}"
            or env.get("HTTP_X_FORWARDED_FOR") or env.get("HTTP_FORWARDED")):
            return self.reply(start,point(403,"Forbidden"))
        path=env["PATH_INFO"];method=env["REQUEST_METHOD"]
        if path=="/style.css" and method=="GET":return self.reply(start,point(200,"OK"),CSS,"text/css")
        if method=="POST" and (env.get("HTTP_ORIGIN")!=self.origin or env.get("HTTP_SEC_FETCH_SITE") not in (None,"same-origin")):
            return self.reply(start,point(403,"Forbidden"))
        def redirect(location,more=()):
            return self.reply(start,point(303,"See Other"),more=(("Location",location),*more))
        with sqlite3.connect(self.db) as db:
            db.row_factory=sqlite3.Row
            if path=="/login" and method=="POST":
                try:f=self.decode(env)
                except (ValueError,UnicodeError):return self.reply(start,point(400,"Bad Request"))
                n=f.get("user","");pw=f.get("password","")
                if len(n)>60 or not 16<=len(pw)<=200:return self.reply(start,point(403,"Forbidden"))
                account=db.execute("SELECT * FROM person WHERE name=?",(n,)).fetchone()
                got=PASS(pw,account["salt"] if account else self.fake_salt)
                if not hmac.compare_digest(got, account["digest"] if account else b"\0"*64) or not account:
                    return self.reply(start,point(403,"Forbidden"),self.page("<p>Sign-in failed.</p><a href='/'>Try again</a>"))
                token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(26)
                db.execute("DELETE FROM session WHERE until < ?",(int(time.time()),))
                db.execute("INSERT INTO session VALUES(?,?,?,?)",(hashlib.sha256(token.encode()).digest(),n,csrf,int(time.time())+3600))
                return redirect("/",(("Set-Cookie","demo="+token+"; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600"),))
            try:
                cookies=SimpleCookie(env.get("HTTP_COOKIE",""))
                token=cookies["demo"].value if "demo" in cookies else ""
            except CookieError:token=""
            key=hashlib.sha256(token.encode()).digest()
            ses=db.execute("SELECT * FROM session WHERE token=? AND until>?",(key,int(time.time()))).fetchone()
            if not ses:
                if method!="GET" or path!="/":return self.reply(start,point(403,"Forbidden"))
                return self.reply(start,point(200,"OK"),self.page(
                  "<section><h1>Sign in to the local demo</h1><form method='post' action='/login'>"
                  "<label>Username <input name='user' autocomplete='username' required></label>"
                  "<label>Password <input name='password' type='password' autocomplete='current-password' required></label>"
                  "<button>Sign in</button></form></section>"))
            actor=ses["name"]; csrf=ses["csrf"]
            if method=="GET" and (path=="/" or path in VIEWS):
                return self.reply(start,point(200,"OK"),self.view(db,actor,csrf,path))
            match=re.fullmatch(r'/(download|scan|upload)/([a-f0-9]{20})',path)
            if match and match[1]=='download' and method=='GET':
                row=db.execute("SELECT * FROM upload WHERE id=? AND status='clean'",(match[2],)).fetchone() if actor=='counsel' else None
                if not row:return self.reply(start,point(404,"Not Found"))
                if not hmac.compare_digest(hashlib.sha256(row["bytes"]).hexdigest(),row["sha"]):return self.reply(start,point(503,"Service Unavailable"))
                return self.reply(start,point(200,"OK"),row["bytes"],"application/octet-stream",(("Content-Disposition","attachment; filename=download"+Path(row["name"]).suffix.lower()+"; filename*=UTF-8''"+quote(row["name"],safe="")),))
            if match and match[1]=='upload' and method=='POST':
                rid=match[2]
                target=db.execute("SELECT id,ref,kind FROM request WHERE id=? AND recipient=? AND hidden=0",(rid,actor)).fetchone() if actor!='counsel' else None
                if not target or not (target["kind"]=="document" or is_interrogatory(target)):
                    return self.reply(start,point(404,"Not Found"))
                try:sent,name,blob=self.multipart(env)
                except (ValueError,UnicodeError,KeyError) as err:
                    msg=str(err) if type(err) is ValueError and str(err) else "Choose a valid PDF or UTF-8 text file under 2 MiB and try again."
                    return self.reply(start,point(400,"Bad Request"),self.page("<section><h1>File not uploaded</h1><p>"+E(msg)+"</p><a href='"+E(request_anchor(target))+"'>Back to this request</a></section>",actor,csrf))
                if not hmac.compare_digest(sent,csrf):return self.reply(start,point(403,"Forbidden"))
                if db.execute("SELECT count(*) FROM upload").fetchone()[0]>=40:return self.reply(start,point(413,"Content Too Large"))
                db.execute("INSERT INTO upload VALUES(?,?,?,?,?,?)",(secrets.token_hex(10),rid,name,hashlib.sha256(blob).hexdigest(),blob,'pending'))
                return redirect(request_anchor(target))
            if method!="POST":return self.reply(start,point(404,"Not Found"))
            try:form=self.decode(env)
            except (ValueError,UnicodeError):return self.reply(start,point(400,"Bad Request"))
            if not hmac.compare_digest(form.get("csrf","").encode(),csrf.encode()):return self.reply(start,point(403,"Forbidden"))
            if match and match[1]=='scan' and actor=='counsel':
                row=db.execute("SELECT upload.*, request.ref, request.kind FROM upload JOIN request ON request.id=upload.req WHERE upload.id=? AND upload.status='pending'",(match[2],)).fetchone()
                if not row:return self.reply(start,point(404,"Not Found"))
                blob=row['bytes']
                if not hmac.compare_digest(hashlib.sha256(blob).hexdigest(),row['sha']):return self.reply(start,point(503,"Service Unavailable"))
                decision=verdict(self.scanner_socket,blob)
                if decision not in {'clean','blocked'}:
                    return self.reply(start,point(503,"Service Unavailable"),self.page("<p>Scanner unavailable. The original remains in quarantine.</p><a href='"+E(request_anchor({"kind":row["kind"],"ref":row["ref"],"id":row["req"]}))+"'>Return to request</a>"))
                db.execute("UPDATE upload SET status=? WHERE id=? AND sha=? AND status='pending'",(decision,row['id'],row['sha']))
                return redirect(request_anchor({"kind":row["kind"],"ref":row["ref"],"id":row["req"]}))
            if path=="/logout":
                db.execute("DELETE FROM session WHERE token=?",(key,))
                return redirect("/",(("Set-Cookie","demo=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),))
            pieces=path.split("/")
            if len(pieces)!=3 or len(pieces[2])!=20:return self.reply(start,point(404,"Not Found"))
            action,rid=pieces[1:]
            r=db.execute("SELECT * FROM request WHERE id=?",(rid,)).fetchone()
            allowed=bool(r and (actor=="counsel" or (r["recipient"]==actor and not r["hidden"])))
            if not allowed:return self.reply(start,point(404,"Not Found"))
            notes=form.get("notes","").strip()
            if len(notes)>3500:return self.reply(start,point(400,"Bad Request"))
            if action=="visibility" and actor=="counsel":
                if not db.execute("SELECT 1 FROM event WHERE request_id=?",(rid,)).fetchone():return self.reply(start,point(409,"Conflict"))
                db.execute("UPDATE request SET hidden=1-hidden WHERE id=?",(rid,))
                return redirect("/")
            if action=="reply" and actor=="counsel" and notes:kind="Counsel reply (private)"
            elif action=="respond" and actor!="counsel":
                kind=form.get("kind","")
                allowed_k={"still_searching","help","not_kept","never_existed","cannot_find"} if r["kind"]=="document" else {"answer","help"}
                if kind not in allowed_k or (kind!="still_searching" and not notes):
                    return self.reply(start,point(400,"Bad Request"),self.page("<p>Choose an action and add an explanation when requested.</p><a href='/'>Return</a>"))
            else:return self.reply(start,point(403,"Forbidden"))
            db.execute("INSERT INTO event(request_id,actor,kind,notes,when_utc) VALUES(?,?,?,?,?)",(rid,actor,kind,notes,int(time.time())))
            return redirect(request_anchor(r))

class NoAccessLog(WSGIRequestHandler):
    def log_message(self,*_args):pass

def main():
    with tempfile.TemporaryDirectory(prefix="discovery-demo-") as tmp, make_server("127.0.0.1",0,lambda _e,_s:[],handler_class=NoAccessLog) as http:
        app=Demo(tmp,http.server_port,os.environ.get('DEMO_CLAMD_SOCKET'))
        http.set_app(app)
        print("LOCAL SYNTHETIC DEMO:",app.origin,flush=True)
        for n,p in app.passwords.items():print(f"{n}: {p}",flush=True)
        print("Do not enter actual case information. Press Ctrl+C to stop.",flush=True)
        try:http.serve_forever()
        except KeyboardInterrupt:pass
if __name__=="__main__":main()
