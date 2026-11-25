import http.client, os, re, tempfile, threading, unittest
from urllib.parse import urlencode
from wsgiref.simple_server import make_server
from portal_demo import Demo,NoAccessLog

class FullLocalDemo(unittest.TestCase):
    def test_browser_entrypoint_and_private_responses(self):
        with tempfile.TemporaryDirectory() as tmp, make_server("127.0.0.1",0,lambda _e,_s:[],handler_class=NoAccessLog) as service:
            app=Demo(tmp,service.server_port,os.environ.get("STARTER_TEST_CLAMD_SOCKET"));service.set_app(app)
            worker=threading.Thread(target=service.serve_forever,daemon=True);worker.start()
            def req(path="/",data=None,cookie=None,origin=None,extra=None,raw=None):
                h=extra or {}
                if cookie:h["Cookie"]=cookie
                p=raw if raw is not None else urlencode(data).encode() if data is not None else None
                if p is not None:
                    h.setdefault("Content-Type","application/x-www-form-urlencoded")
                    h["Origin"]=origin or app.origin
                c=http.client.HTTPConnection("127.0.0.1",service.server_port,timeout=4)
                try:
                    c.request("GET" if p is None else "POST",path,p,h)
                    resp=c.getresponse()
                    return resp.status,resp.read().decode(),resp.getheader("Set-Cookie")
                finally:c.close()
            def login(name):
                status,_,cookie=req("/login",{"user":name,"password":app.passwords[name]})
                self.assertEqual(status,303)
                cookie=cookie.split(";")[0]
                _,page,_=req(cookie=cookie)
                token=re.search("name='csrf' value='([^']+)'",page)[1]
                return cookie,token,page
            try:
                self.assertIn("Local demo",req()[1])
                # Browser POSTs need the same-origin referrer policy to retain Origin.
                c=http.client.HTTPConnection("127.0.0.1",service.server_port,timeout=4)
                try:
                    c.request("GET","/")
                    self.assertEqual(c.getresponse().getheader("Referrer-Policy"),"same-origin")
                finally:c.close()
                self.assertEqual(req(extra={"Host":"remote.example.invalid"})[0],403)
                w,wcsrf,wp=login("witness")
                r,rcsrf,rp=login("records")
                a,acsrf,ap=login("counsel")
                self.assertIn("Interrogatory 1",wp);self.assertNotIn("Interrogatory 1",rp)
                rog_page=req("/interrogatories",cookie=w)[1]
                rfa_page=req("/admissions",cookie=w)[1]
                rpd_page=req("/documents",cookie=w)[1]
                self.assertIn("<mark>lantern exhibition</mark>",rog_page)
                self.assertIn("Definitions ¶ 1",rog_page)
                self.assertIn("The display of demonstration lanterns in the observatory",rog_page)
                self.assertIn("Exact definition from the request:",rog_page)
                self.assertIn("In plain English:",rog_page)
                self.assertIn("not another exhibit or another night.",rog_page)
                self.assertNotIn("The paper or electronic list",rog_page)
                self.assertIn("Either format counts.",rpd_page)
                self.assertNotIn("<h2>Admission 1</h2>",rog_page)
                self.assertIn("<h2>Admission 1</h2>",rfa_page)
                self.assertNotIn("<h2>Interrogatory 1</h2>",rfa_page)
                self.assertIn("<mark>checkout sheet</mark>",rpd_page)
                self.assertNotIn("<h2>Interrogatory 1</h2>",rpd_page)
                self.assertIn("No requests of this type",req("/admissions",cookie=r)[1])
                self.assertIn("exhibit setup instructions",rp);self.assertNotIn("exhibit setup instructions",wp)
                wp_path=re.search("action='(/respond/[^']+)'",wp)[1]
                r_path=re.search("action='(/respond/[^']+)'",rp)[1]
                self.assertEqual(req(wp_path,{"csrf":rcsrf,"kind":"answer","notes":"Not mine"},r)[0],404)
                self.assertEqual(req(wp_path,{"csrf":"wrong","kind":"answer","notes":"test"},w)[0],403)
                self.assertEqual(req(wp_path,{"csrf":wcsrf,"kind":"answer","notes":"test"},w,"https://elsewhere.invalid")[0],403)
                self.assertEqual(req(wp_path,{"csrf":wcsrf,"kind":"answer","notes":"I saw an invented blue lantern."},w)[0],303)
                self.assertEqual(req(r_path,{"csrf":rcsrf,"kind":"still_searching","notes":""},r)[0],303)
                self.assertEqual(req(r_path,{"csrf":rcsrf,"kind":"help","notes":"Where should I look?"},r)[0],303)
                a_page=req(cookie=a)[1]
                self.assertIn("Where should I look?",a_page)
                self.assertNotIn("Where should I look?",req(cookie=w)[1])
                self.assertIn("invented blue lantern",a_page)
                upload=r_path.replace("/respond/","/upload/")
                data_text=b"Fictional observatory inventory.\n"
                parts=(
                   '--DEMOBOUNDARY\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n'+rcsrf+
                   '\r\n--DEMOBOUNDARY\r\nContent-Disposition: form-data; name="file"; filename="observatory.txt"\r\nContent-Type: text/plain\r\n\r\n'
                ).encode()+data_text+b'\r\n--DEMOBOUNDARY--\r\n'
                mime={"Content-Type":"multipart/form-data; boundary=DEMOBOUNDARY"}
                self.assertEqual(req(upload,raw=parts,cookie=w,extra=dict(mime))[0],404)
                self.assertEqual(req(upload,raw=parts,cookie=r,extra=dict(mime))[0],303)
                counsel_docs=req("/documents",cookie=a)[1]
                self.assertIn("observatory.txt · pending",counsel_docs)
                scan=re.search("action='(/scan/[^']+)'",counsel_docs)[1]
                download=scan.replace("/scan/","/download/")
                self.assertEqual(req(download,cookie=a)[0],404)
                self.assertEqual(req(download,cookie=r)[0],404)
                call=req(scan,{"csrf":acsrf},a)
                if app.scanner_socket:
                    self.assertEqual(call[0],303)
                    self.assertEqual(req(download,cookie=a)[:2],(200,data_text.decode()))
                    self.assertEqual(req(download,cookie=r)[0],404)
                else:
                    self.assertEqual(call[0],503)
                    self.assertEqual(req(download,cookie=a)[0],404)
                self.assertNotIn("observatory.txt",req("/documents",cookie=w)[1])
                # A ROG attachment belongs to the exact assigned question, not the RFA or RPD.
                rog=re.search(r"<section id='request-([a-f0-9]+)'><h2>Interrogatory 1</h2>(.*?)</section>",wp,re.S)
                rfa=re.search(r"<section id='request-([a-f0-9]+)'><h2>Admission 1</h2>(.*?)</section>",wp,re.S)
                self.assertIn("Supporting documents (optional)",rog[2])
                self.assertNotIn("Supporting documents (optional)",rfa[2])
                rog_upload="/upload/"+rog[1]
                self.assertEqual(req("/respond/"+rog[1],{"csrf":wcsrf,"kind":"answer","notes":"I have no attachment."},w)[0],303)
                self.assertEqual(req(rog_upload,raw=parts,cookie=r,extra=dict(mime))[0],404)
                supporting=parts.replace(rcsrf.encode(),wcsrf.encode()).replace(b"observatory.txt",b"supporting.txt")
                self.assertEqual(req("/upload/"+rfa[1],raw=supporting,cookie=w,extra=dict(mime))[0],404)
                invalid=req(rog_upload,raw=supporting.replace(b"supporting.txt",b"supporting.docx"),cookie=w,extra=dict(mime))
                self.assertEqual(invalid[0],400)
                self.assertIn("accepts PDF and text",invalid[1])
                self.assertEqual(req(rog_upload,raw=supporting,cookie=w,extra=dict(mime))[0],303)
                self.assertEqual(req(rog_upload,raw=supporting.replace(b"supporting.txt",b"second.txt"),cookie=w,extra=dict(mime))[0],303)
                counsel_rog=re.search(r"<h2>Interrogatory 1</h2>(.*?)</section>",req(cookie=a)[1],re.S)[1]
                self.assertIn("I have no attachment.",counsel_rog)
                self.assertIn("supporting.txt · pending",counsel_rog)
                self.assertIn("second.txt · pending",counsel_rog)
                self.assertNotIn("supporting.txt",req("/documents",cookie=a)[1])
                self.assertNotIn("supporting.txt",req(cookie=r)[1])
                rog_scan=re.search("action='(/scan/[^']+)'",counsel_rog)[1]
                rog_download=rog_scan.replace("/scan/","/download/")
                self.assertEqual(req(rog_download,cookie=a)[0],404)
                if app.scanner_socket:
                    self.assertEqual(req(rog_scan,{"csrf":acsrf},a)[0],303)
                    self.assertEqual(req(rog_download,cookie=a)[:2],(200,data_text.decode()))
                    self.assertEqual(req(rog_download,cookie=w)[0],404)

                self.assertEqual(req(wp_path.replace("/respond/","/visibility/"),{"csrf":acsrf},a)[0],303)
                self.assertNotIn("invented blue lantern",req(cookie=w)[1])
                self.assertIn("invented blue lantern",req(cookie=a)[1])
            finally:service.shutdown();worker.join()
