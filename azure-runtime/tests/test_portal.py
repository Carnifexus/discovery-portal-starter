"""Synthetic-only browser and API checks. The injected fixture scanner tests verdict handling, not the real scanner."""
import hashlib, io, json, os, secrets, tempfile, unittest
from pathlib import Path
from pypdf import PdfWriter
from portal import Portal, COOKIE
from screening import Rejected, ScannerOffline, MAX_BYTES

class FixtureScanner:
    def __init__(self):self.scanned=[];self.outcome='ok'
    def scan(self,body):
        self.scanned.append(hashlib.sha256(body).hexdigest())
        if self.outcome=='offline':raise ScannerOffline('scanner_unavailable')
        if self.outcome=='blocked':raise Rejected('unsafe_file')
def pdf():
    w=PdfWriter();w.add_blank_page(width=250,height=250);w.add_metadata({'/Title':'Original synthetic document metadata'})
    b=io.BytesIO();w.write(b);return b.getvalue()
class TestPortal(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.db=self.base/'sample.db';self.raw=pdf()
        self.scanner=FixtureScanner()
        self.origin='http://127.0.0.1:8080'
        self.portal=Portal(self.db,secrets.token_bytes(32),self.origin,self.scanner,demo=True,init=True)
        self.passwords={u:secrets.token_urlsafe(24) for u in ('client-one','client-two','counsel-test')}
        with self.portal.tx(True) as c:
            self.p1=self.portal.create_matter(c,'Fictional sample matter');self.p2=self.portal.create_matter(c,'Another synthetic matter')
            self.id1=self.portal.register(c,'client-one',self.passwords['client-one'],'client',self.p1)
            self.portal.register(c,'client-two',self.passwords['client-two'],'client',self.p2)
            self.portal.register(c,'counsel-test',self.passwords['counsel-test'],'counsel',None)
            self.r1=self.portal.add_request(c,self.p1,'Monthly statement','Upload the synthetic March statement.','documents')
            self.r2=self.portal.add_request(c,self.p1,'Records location','Where did the sample company keep statements?','question')
            self.r_other=self.portal.add_request(c,self.p2,'Other materials','This is not your matter.','documents')
        self.url='/api/matters/'+self.p1
        self.upload_url=self.url+'/requests/'+self.r1+'/files'
    def raw_call(self,path,method,body,headers):
        e={'REQUEST_METHOD':method,'PATH_INFO':path,'wsgi.input':io.BytesIO(body or b''),'REMOTE_ADDR':'127.0.0.1',
           'HTTP_HOST':'127.0.0.1:8080','CONTENT_LENGTH':str(len(body or b''))}
        for k,v in headers.items():
            key=k.upper().replace('-','_')
            e[key if key in ('CONTENT_TYPE','CONTENT_LENGTH') else 'HTTP_'+key]=v
        result=[]
        data=b''.join(self.portal(e,lambda status,headers:result.extend([int(status.split()[0]),dict(headers)])))
        return result[0],result[1],data
    def call(self,path,method='GET',body=None,session=None,more=None):
        headers={}
        if method=='POST':headers['Origin']=self.origin
        if session:headers['Cookie']=session[0];headers['X-CSRF-Token']=session[1]
        if isinstance(body,dict):body=json.dumps(body).encode();headers['Content-Type']='application/json'
        if more:headers.update(more)
        n,h,d=self.raw_call(path,method,body,headers)
        return n,h,json.loads(d) if h['Content-Type'].startswith('application/json') else d
    def login(self,user):
        n,h,_=self.call('/api/sign-in','POST',{'username':user,'password':self.passwords[user]});self.assertEqual(n,200)
        ck=h['Set-Cookie'];self.assertTrue({'Secure','SameSite=Strict','HttpOnly'}.issubset({v.strip() for v in ck.split(';')[1:]}))
        ck=ck.split(';',1)[0];n,_,data=self.call('/api/session',session=(ck,''));self.assertEqual(n,200)
        return ck,data['csrf']
    def upload(self,session,n='March.pdf',data=None,path=None):
        return self.call(path or self.upload_url,'POST',self.raw if data is None else data,session,
                         {'Content-Type':'application/octet-stream','X-File-Name':n})
    def test_file_gates_and_isolation(self):
        client=self.login('client-one');other=self.login('client-two');counsel=self.login('counsel-test')
        self.assertEqual(self.call(self.url)[0],401)
        self.assertEqual(self.call(self.url,session=other)[0],404)
        self.assertEqual(self.upload(other)[0],404)
        self.assertEqual(self.upload(client,'March.exe')[0],415)
        self.assertEqual(self.upload(client,'March.pdf',b'ordinary text masquerading as a PDF')[0],415)
        self.assertEqual(self.upload(client,'March.pdf',b'x'*(MAX_BYTES+1))[0],413)
        self.assertEqual(self.call(self.upload_url,'POST',self.raw,client,{'Origin':'https://unrelated.invalid','Content-Type':'application/octet-stream'})[0],403)
        self.assertEqual(len(self.scanner.scanned),0)
        self.scanner.outcome='offline'
        self.assertEqual(self.upload(client)[0],503)
        self.scanner.outcome='blocked'
        self.assertEqual(self.upload(client)[0],415)
        self.scanner.outcome='ok'
        self.assertEqual(self.call(self.url,session=counsel)[2]['requests'][0]['files'],[])
        self.assertEqual(self.upload(counsel)[0],403)
        n,_,x=self.upload(client);self.assertEqual(n,201);self.assertEqual(x['sha256'],hashlib.sha256(self.raw).hexdigest())
        f=x['fileId'];p=self.url+'/files/'+f
        self.assertEqual(self.upload(client)[2]['status'],'already_received')
        self.assertEqual(self.call(p,session=client)[0],403);self.assertEqual(self.call(p,session=other)[0],404)
        s,h,b=self.call(p,session=counsel);self.assertEqual(s,200);self.assertEqual(b,self.raw);self.assertEqual(h['Content-Type'],'application/octet-stream');self.assertIn('attachment',h['Content-Disposition'])
        self.assertNotIn(self.raw,self.db.read_bytes());self.assertNotIn(b'March.pdf',self.db.read_bytes())
        self.assertEqual(self.call(p+'/review','POST',{'status':'held','note':'Counsel test note'},counsel)[0],200)
        self.assertNotIn('Counsel test note',json.dumps(self.call(self.url,session=client)[2]))
        self.assertEqual(self.call(self.url+'/requests/'+self.r1+'/review','POST',{'status':'complete','note':''},counsel)[0],200)
        self.assertEqual(self.upload(client)[0],409)
        with self.portal.tx(True) as c:self.portal.revoke(c,self.id1)
        self.assertEqual(self.call(self.url,session=client)[0],401)
        self.assertEqual(self.call(p,session=counsel)[2],self.raw)
    def test_drafts_batch_and_followup(self):
        cli=self.login('client-one');co=self.login('counsel-test')
        d=self.url+'/requests/'+self.r2
        self.assertEqual(self.call(d+'/draft','POST',{'kind':'clarification','text':'Synthetic draft'},cli)[0],200)
        self.assertNotIn('Synthetic draft',json.dumps(self.call(self.url+'/report',session=co)[2]))
        self.assertIn('Synthetic draft',json.dumps(self.call(self.url,session=cli)[2]))
        self.assertEqual(self.call(self.url+'/submit','POST',{'responses':[{'id':self.r1,'kind':'uploaded','text':''}]},cli)[0],409)
        self.assertEqual(self.upload(cli)[0],201)
        b={'responses':[{'id':self.r1,'kind':'uploaded','text':''},{'id':self.r2,'kind':'clarification','text':'What period?'}]}
        s,_,out=self.call(self.url+'/submit','POST',b,cli);self.assertEqual(s,201);self.assertEqual(out['count'],2)
        t,_,again=self.call(self.url+'/submit','POST',b,cli)
        self.assertEqual((t,again['receipt'],again['status']),(200,out['receipt'],'already_received'))
        altered={'responses':b['responses'][:1]}
        self.assertEqual(self.call(self.url+'/submit','POST',altered,cli)[0],409)
        self.assertIn('What period?',json.dumps(self.call(self.url+'/report',session=co)[2]))
        self.assertEqual(self.call(d+'/follow-up','POST',{'text':'March only'},co)[0],200)
        self.assertIn('March only',json.dumps(self.call(self.url,session=cli)[2]))
        g=self.call(self.url+'/requests','POST',{'type':'question','title':'Oops'},co);self.assertEqual(g[0],400)
        self.assertEqual(self.call(self.url+'/requests','POST',{'kind':'question','title':'A follow-up','details':'Which office?'},co)[0],201)
    def test_counsel_provisions_isolated_intake(self):
        cli=self.login('client-one');co=self.login('counsel-test')
        b={'title':'Fictional intake created by counsel','username':'new-test-client','password':secrets.token_urlsafe(24),'requests':[
            {'title':'Statement','details':'Upload synthetic records.','kind':'documents'},
            {'title':'Date','details':'When did this happen?','kind':'question'}]}
        self.assertEqual(self.call('/api/matters','POST',b,cli)[0],403)
        old=self.call('/api/matters',session=co)[2]
        broken={**b,'requests':b['requests']+[{'title':'Invalid','details':'Missing kind'}]}
        self.assertEqual(self.call('/api/matters','POST',broken,co)[0],400)
        self.assertEqual(self.call('/api/matters',session=co)[2],old)
        n,_,y=self.call('/api/matters','POST',b,co);self.assertEqual(n,201)
        self.assertEqual(self.call('/api/matters','POST',b,co)[0],409)
        self.passwords[b['username']]=b['password'];person=self.login(b['username'])
        u='/api/matters/'+y['id']
        self.assertEqual(self.call(u,session=cli)[0],404)
        self.assertEqual(self.call(self.url,session=person)[0],404)
        self.assertEqual(self.call(u+'/report',session=person)[0],403)
        packet=self.call(u,session=person)[2];self.assertEqual(len(packet['requests']),2)
        resp={'responses':[{'id':packet['requests'][0]['id'],'kind':'unknown','text':''}]}
        self.assertEqual(self.call(u+'/submit','POST',resp,person)[2]['error'],'use_document_page')
        report=self.call(u+'/report',session=co)[2]
        self.assertEqual(report['audit'][0]['event'],'matter_created')
        self.assertNotIn(b['password'],json.dumps(report))
        self.assertNotIn(b['password'].encode(),self.db.read_bytes())
    def test_activity_is_counsel_only_and_excludes_contents(self):
        cli=self.login('client-one');other=self.login('client-two');co=self.login('counsel-test')
        feed=self.url+'/activity'
        self.assertEqual(self.call(feed,session=other)[0],404)
        self.assertEqual(self.call(feed,session=cli)[0],403)
        st,_,f=self.upload(cli);self.assertEqual(st,201)
        answers={'responses':[{'id':self.r1,'kind':'uploaded','text':''},{'id':self.r2,'kind':'clarification','text':'private question content'}]}
        self.assertEqual(self.call(self.url+'/submit','POST',answers,cli)[0],201)
        self.assertEqual(self.call(self.url+'/files/'+f['fileId']+'/review','POST',{'status':'held','note':'private analysis'},co)[0],200)
        feedbody=self.call(feed,session=co)[2]
        self.assertEqual([e['event'] for e in feedbody['entries']],['file_reviewed','batch_submitted','file_received'])
        self.assertEqual(feedbody['entries'][0]['requestId'],self.r1)
        self.assertEqual(feedbody['entries'][1]['count'],2)
        self.assertNotIn('March.pdf',json.dumps(feedbody))
        self.assertNotIn('private',json.dumps(feedbody))
        self.assertFalse(feedbody['more'])

if __name__=='__main__':unittest.main(verbosity=2)
