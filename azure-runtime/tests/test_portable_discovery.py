"""Synthetic role, assignment, and quarantine checks through the application APIs."""
import json
import unittest
from pathlib import Path

from test_quarantine_stage import StageTest

class FullDiscoveryBeta(unittest.TestCase):
  def test_session_cookie_scope(self):
    from config import cookie_domain_mode, deployment_host, storage_settings
    from portal import Portal
    p=Portal.__new__(Portal)
    p.host='example-discovery.azurewebsites.net'
    p.exact_cookie_domain=cookie_domain_mode('https://'+p.host)
    cookie=p.session_cookie('sample',60)
    self.assertTrue(cookie.startswith('__Secure-discovery-intake-azure=sample;'))
    self.assertIn('Domain='+p.host,cookie)
    self.assertIn('Path=/; Secure; HttpOnly; SameSite=Strict',cookie)
    p.host='private.example.invalid'
    p.exact_cookie_domain=cookie_domain_mode('https://'+p.host)
    self.assertTrue(p.session_cookie('sample',60).startswith('__Host-'))
    self.assertNotIn('Domain=',p.session_cookie('sample',60))
    self.assertTrue(cookie_domain_mode('https://'+p.host,'azure-exact-domain'))
    self.assertFalse(cookie_domain_mode('https://example-discovery.azurewebsites.net','host'))
    self.assertTrue(cookie_domain_mode('https://example-discovery-a6gqaeashthkhkeu.eastus-01.azurewebsites.net'))
    self.assertFalse(cookie_domain_mode('https://eastus-01.azurewebsites.net.tenant.example.invalid'))
    with self.assertRaises(ValueError):
      cookie_domain_mode('https://nested.example.azurewebsites.net','azure-exact-domain')
    for invalid in ('http://private.example.invalid','https://private.example.invalid/',
                    'https://private.example.invalid:443','https://user@private.example.invalid'):
      with self.assertRaises(ValueError):deployment_host(invalid)
    with self.assertRaises(ValueError):cookie_domain_mode('https://example.invalid','azure-exact-domain')
    with self.assertRaises(ValueError):storage_settings('https://demoaccount.blob.core.windows.net','one','one')
    self.assertEqual(storage_settings('https://demoaccount.blob.core.windows.net/', 'state-one','files-one'),
                     ('https://demoaccount.blob.core.windows.net','state-one','files-one'))
  def test_import_arbitrary_order_and_interrogatory_attachments(self):
    x=StageTest()
    self.addCleanup(x.doCleanups)
    x.setUp()
    requests=json.loads((Path(__file__).parent.parent/'fictional-import-example.json').read_text())
    counsel=x.login('counsel-test')
    password=x.passwords['client-one']
    status,_,matter=x.call('/api/matters','POST',{'title':'Fictional observatory','username':'new-witness','password':password,'requests':requests,'assignAll':False},counsel)
    self.assertEqual(status,201)
    path='/api/matters/'+matter['id']
    x.passwords['new-witness']=password
    client=x.login('new-witness'); outsider=x.login('client-two')
    self.assertEqual(x.call(path,session=client)[2]['requests'],[])
    co_view=x.call(path,session=counsel)[2]
    for row in co_view['requests']:
      n,_,_=x.call(path+'/requests/'+row['id']+'/assignments','POST',{'respondentId':co_view['respondents'][0]['id']},counsel)
      self.assertEqual(n,201)
    _,_,view=x.call(path,session=client)
    rog,rpd,rfa=view['requests']
    self.assertEqual([r['category'] for r in (rog,rpd,rfa)],['rog','rpd','rfa'])
    self.assertEqual(rog['definitions'],requests[0]['definitions'])
    early={'responses':[{'id':rfa['id'],'kind':'false_input','text':'Not digital.'}]}
    self.assertEqual(x.call(path+'/submit','POST',early,client)[0],201)
    self.assertEqual(x.call(path+'/submit','POST',early,client)[0],200)
    upload=path+'/requests/'+rog['id']+'/files'
    self.assertEqual(x.upload(outsider,path=upload)[0],404)
    self.assertEqual(x.upload(client,path=path+'/requests/'+rfa['id']+'/files')[0],409)
    n,_,file=x.upload(client,path=upload)
    self.assertEqual((n,file['status']),(201,'pending'))
    download=path+'/files/'+file['fileId']
    self.assertEqual(x.call(download,session=counsel)[0],404)
    n,work=x.worker('claim',{},x.secret)
    self.assertEqual(n,200)
    n,_=x.worker('verdict',{k:work[k] for k in ('id','lease','sha256')}|{'verdict':'clean'},x.secret)
    self.assertEqual(n,200)
    self.assertEqual(x.call(download,session=counsel)[2],x.raw)
    self.assertEqual(x.call(path+'/submit','POST',{'responses':[{'id':rog['id'],'kind':'answer','text':'Fictional answer.'}]},client)[0],201)
    self.assertEqual(x.call(path+'/requests/'+rpd['id']+'/production-status','POST',{'kind':'searching','text':''},client)[0],201)
  def test_fictional_roles_can_be_provisioned_and_revoked(self):
    x=StageTest()
    self.addCleanup(x.doCleanups)
    x.setUp()
    requests=json.loads((Path(__file__).parent.parent/'fictional-import-example.json').read_text())
    counsel=x.login('counsel-test')
    witness='fictional-witness'; custodian='fictional-custodian'
    a=x.passwords['client-one']; b=x.passwords['client-two']
    n,_,m=x.call('/api/matters','POST',{'title':'Fictional observatory','username':witness,
       'password':a,'requests':requests,'assignAll':False},counsel)
    self.assertEqual(n,201)
    route='/api/matters/'+m['id']
    n,_,cust=x.call(route+'/respondents','POST',{'username':custodian,'password':b},counsel)
    self.assertEqual(n,201)
    packet=x.call(route,session=counsel)[2]
    pid=next(i['id'] for i in packet['respondents'] if i['username']==witness)
    for row in packet['requests']:
      aid=cust['id'] if row['category']=='rpd' else pid
      self.assertEqual(x.call(route+'/requests/'+row['id']+'/assignments','POST',
                              {'respondentId':aid},counsel)[0],201)
    x.passwords[witness]=a; x.passwords[custodian]=b
    w=x.login(witness); c=x.login(custodian)
    self.assertEqual({j['category'] for j in x.call(route,session=w)[2]['requests']},{'rog','rfa'})
    self.assertEqual({j['category'] for j in x.call(route,session=c)[2]['requests']},{'rpd'})
    self.assertEqual(x.call(route+'/respondents/'+pid+'/revoke','POST',{},w)[0],403)
    self.assertEqual(x.call(route+'/respondents/'+pid+'/revoke','POST',{},counsel)[0],200)
    self.assertEqual(x.call(route,session=w)[0],401)
    self.assertEqual(x.call(route,session=c)[0],200)

def load_tests(loader,_tests,_pattern):return loader.loadTestsFromTestCase(FullDiscoveryBeta)
