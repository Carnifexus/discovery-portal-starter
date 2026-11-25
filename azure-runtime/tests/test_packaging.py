"""Operator-facing checks against fictional inputs and the Azure adapter."""
import hashlib
import io
import json
import os
import secrets
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from config import cookie_domain_mode
from seed import write_seed
from storage import SnapshotApp

ROOT=Path(__file__).resolve().parent.parent
ORIGIN='https://example-discovery.azurewebsites.net'

class OperatorEntryPoints(unittest.TestCase):
    def test_zip_cli_allowlist_permissions_and_repeatability(self):
        with tempfile.TemporaryDirectory() as tmp:
            files=[Path(tmp)/n for n in ('a.zip','b.zip')]
            for p in files:
                subprocess.run([sys.executable,str(ROOT/'build-azure-zip.py'),str(p)],check=True)
                self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
            self.assertEqual(hashlib.sha256(files[0].read_bytes()).digest(),
                             hashlib.sha256(files[1].read_bytes()).digest())
            with ZipFile(files[0]) as z:
                self.assertIsNone(z.testzip())
                self.assertEqual(set(z.namelist()),{'config.py','function_app.py','host.json','portal.py',
                    'quarantine.py','screening.py','storage.py','requirements.txt',
                    'web/index.html','web/app.css','web/app.js'})
                self.assertTrue(all((x.external_attr>>16)==0o100644 for x in z.infolist()))

    def test_new_encrypted_state_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'seed.blob'; db=Path(tmp)/'validation.sqlite'
            key=secrets.token_bytes(32);token=secrets.token_urlsafe(48)
            pw=secrets.token_urlsafe(24)
            write_seed(f,ORIGIN,key,token,'test-counsel',pw,
                       {n:secrets.token_urlsafe(24) for n in ('demo-witness','demo-custodian')})
            self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o600)
            box=f.read_bytes()
            self.assertNotIn(pw.encode(),box)
            self.assertNotIn(b'Fictional observatory',box)
            db.write_bytes(SnapshotApp(None,None,key,ORIGIN,token).unseal(box))
            with sqlite3.connect(db) as c:
                self.assertEqual(c.execute('SELECT COUNT(*) FROM request').fetchone(),(3,))
                self.assertEqual(c.execute('SELECT COUNT(*) FROM account').fetchone(),(3,))
                self.assertEqual(c.execute('SELECT COUNT(*) FROM assignment').fetchone(),(3,))

    def test_azure_http_entrypoint_with_fictional_encrypted_state(self):
        try:
            import azure.functions as af
            from unittest.mock import patch
            import function_app as adapter
        except ModuleNotFoundError:
            self.skipTest('Install the Azure SDK dependencies from requirements.txt')
        from test_quarantine_stage import MemoryStore
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'fictional.blob'
            key=secrets.token_bytes(32);token=secrets.token_urlsafe(48)
            pw=secrets.token_urlsafe(24)
            write_seed(p,ORIGIN,key,token,'test-counsel',pw)
            store=MemoryStore()
            store.state=p.read_bytes()
            app=SnapshotApp(store,store,key,ORIGIN,token,
                            exact_cookie_domain=cookie_domain_mode(ORIGIN))
            def req(path, method='GET', payload=None, headers=None):
                return adapter.handle(af.HttpRequest(method,ORIGIN+path,
                    headers={'Host':'example-discovery.azurewebsites.net'}|(headers or {}),params={}, route_params={},
                    body=json.dumps(payload).encode() if payload is not None else b''),None)
            with patch.object(adapter,'runtime',return_value=app):
                self.assertEqual(req('/').status_code,200)
                self.assertEqual(req('/api/session').status_code,401)
                login=req('/api/sign-in','POST',{'username':'test-counsel','password':pw},
                          {'Origin':ORIGIN,'Content-Type':'application/json'})
                self.assertEqual(login.status_code,200)
                cookie=login.headers['Set-Cookie']
                self.assertIn('Domain=example-discovery.azurewebsites.net',cookie)
                session=req('/api/session',headers={'Cookie':cookie.split(';',1)[0]})
                self.assertEqual(session.status_code,200)
