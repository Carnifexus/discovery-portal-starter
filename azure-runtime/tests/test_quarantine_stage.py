"""One integrated synthetic case for VM-free flow; no real client data or endpoint."""
import hashlib
import os
import secrets
import unittest
from pathlib import Path

from local_worker import process
from portal import COOKIE
from quarantine import QuarantinePortal
from screening import ScannerOffline
from storage import SnapshotApp, StoreUnavailable
from test_portal import TestPortal

class MemoryStore:
    def __init__(self):
        self.objects={}
        self.state=None
        self.version=0
        self.conflict=False
    def put_once(self,key,value):self.objects.setdefault(key,value)
    def get(self,key,cap):
        if key not in self.objects or len(self.objects[key])>cap:raise StoreUnavailable()
        return self.objects[key]
    def get_state(self): return self.state,self.version
    def replace_state(self,data,etag):
        if etag!=self.version or self.conflict:raise StoreUnavailable()
        self.state=data
        self.version+=1

class StageTest(TestPortal):
    def setUp(self):
        # Reuse only the API harness, not the synchronous-path tests.
        super().setUp()
        self.stage_key=secrets.token_bytes(32)
        self.secret=secrets.token_urlsafe(48)
        self.origin='https://stage-v2.example.invalid'
        real=self.raw_call
        def https(path,method,body,headers):
            headers=dict(headers)
            h=headers.get('Origin')
            if h==self.origin:headers['Origin']=self.origin
            import io
            e={'REQUEST_METHOD':method,'PATH_INFO':path,'wsgi.input':io.BytesIO(body or b''),'REMOTE_ADDR':'127.0.0.1',
               'HTTP_HOST':'stage-v2.example.invalid','CONTENT_LENGTH':str(len(body or b''))}
            for k,v in headers.items():
                name=k.upper().replace('-','_')
                e[name if name in ('CONTENT_TYPE','CONTENT_LENGTH') else 'HTTP_'+name]=v
            response=[]
            data=b''.join(self.portal(e,lambda status,heads:response.extend([int(status.split()[0]),dict(heads)])))
            return response[0],response[1],data
        self.raw_call=https
        statefile=Path(self.tmp.name)/'stage.sqlite'
        self.store=MemoryStore()
        p=QuarantinePortal(statefile,self.stage_key,self.origin,self.store,self.secret,init=True)
        with p.tx(True) as c:
            self.p1=p.create_matter(c,'Synthetic first matter')
            p.register(c,'client-one',self.passwords['client-one'],'client',self.p1)
            self.r1=p.add_request(c,self.p1,'Synthetic document','Source sample','documents')
            self.p2=p.create_matter(c,'Synthetic second matter')
            p.register(c,'client-two',self.passwords['client-two'],'client',self.p2)
            p.register(c,'counsel-test',self.passwords['counsel-test'],'counsel',None)
        self.url='/api/matters/'+self.p1
        self.upload_url=self.url+'/requests/'+self.r1+'/files'
        self.portal=SnapshotApp(self.store,self.store,self.stage_key,self.origin,self.secret)
        self.store.state=self.portal.seal(statefile.read_bytes())

    def worker(self,path,body,token):
        import json
        code,_,raw=self.raw_call('/internal/scan/'+path,'POST',json.dumps(body).encode(),
           {'Content-Type':'application/json','Authorization':'Bearer '+token})
        return code,json.loads(raw)

class IntegratedStage(unittest.TestCase):
    def test_pending_clean_blocked_retry_and_original_metadata(self):
        x=StageTest()
        self.addCleanup(x.doCleanups)
        x.setUp()
        client=x.login('client-one'); other=x.login('client-two'); counsel=x.login('counsel-test')
        self.assertEqual(x.upload(other)[0],404)
        n,_,a=x.upload(client)
        self.assertEqual((n,a['status']),(201,'pending'))
        path=x.url+'/files/'+a['fileId']
        self.assertEqual(x.call(path,session=counsel)[0],404)
        self.assertEqual(x.call(x.url,session=counsel)[2]['requests'][0]['files'],[])
        self.assertEqual(x.call(x.url+'/submit','POST',{'responses':[{'id':x.r1,'kind':'uploaded','text':''}]},client)[0],409)
        self.assertEqual(x.worker('claim',{},'nope')[0],404)
        self.assertTrue(all(x.raw not in v for v in x.store.objects.values()))
        self.assertNotIn(b'March.pdf',x.store.state)
        class Remote:
            def __init__(self):self.count=0;self.block=False;self.last=None
            def call(self,part,body,limit):
                self.count+=1
                if part=='verdict':self.last=body
                code,payload=x.worker(part,body,x.secret)
                if code!=200:raise OSError()
                return payload
        class Scanner:
            offline=True
            block=False
            def require_fresh_database(self):
                if self.offline:raise ScannerOffline()
            def scan(self,b):
                if self.block:
                    from screening import Rejected
                    raise Rejected('unsafe_file')
        s=Scanner();r=Remote()
        with self.assertRaises(ScannerOffline):process(r,s)
        self.assertEqual(r.count,0)
        self.assertEqual(x.upload(client)[2]['fileId'],a['fileId'])
        s.offline=False
        x.store.conflict=True
        self.assertEqual(x.worker('claim',{},x.secret)[0],503)
        x.store.conflict=False
        self.assertTrue(process(r,s))
        self.assertEqual(x.worker('verdict',r.last,x.secret)[0],200)
        self.assertEqual(x.worker('verdict',r.last|{'sha256':'0'*64},x.secret)[0],409)
        self.assertEqual(x.call(path,session=counsel)[2],x.raw)
        self.assertEqual(x.call(path,session=other)[0],404)
        self.assertEqual(x.call(x.url+'/submit','POST',{'responses':[{'id':x.r1,'kind':'uploaded','text':''}]},client)[0],201)
        s.block=True
        n,_,b=x.upload(client,data=x.raw+b'\n')
        self.assertEqual((n,b['status']),(201,'pending'))
        self.assertTrue(process(r,s))
        self.assertEqual(x.call(x.url+'/files/'+b['fileId'],session=counsel)[0],404)
        out=x.call(x.url,session=counsel)[2]['requests'][0]
        self.assertEqual(len(out['files']),1)
        self.assertEqual(out['quarantine'],[{'state':'blocked'}])
        self.assertTrue(all(x.raw not in v for v in x.store.objects.values()))
def load_tests(loader, _tests, _pattern):
    return loader.loadTestsFromTestCase(IntegratedStage)
