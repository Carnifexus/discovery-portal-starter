"""Optional Chromium browser smoke against the same Azure HTTP adapter, with no network."""
import json
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from config import cookie_domain_mode
from seed import write_seed
from storage import SnapshotApp
from test_quarantine_stage import MemoryStore

@unittest.skipUnless(os.environ.get('RUN_BROWSER_TEST')=='1','Optional Playwright/Chromium browser check')
class BrowserSmoke(unittest.TestCase):
    def test_fictional_witness_and_counsel(self):
        import azure.functions as af
        from playwright.sync_api import sync_playwright, expect
        from unittest.mock import patch
        import function_app as adapter

        origin='https://example-discovery.azurewebsites.net'
        host=urlsplit(origin).netloc
        key=secrets.token_bytes(32); worker=secrets.token_urlsafe(48)
        counsel_pw=secrets.token_urlsafe(24); witness_pw=secrets.token_urlsafe(24)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'state'
            write_seed(p,origin,key,worker,'test-counsel',counsel_pw,
                       {'demo-witness':witness_pw,'demo-custodian':secrets.token_urlsafe(24)})
            store=MemoryStore();store.state=p.read_bytes()
            app=SnapshotApp(store,store,key,origin,worker,exact_cookie_domain=cookie_domain_mode(origin))

            def route_requests(route):
                r=route.request
                # Cancel any request not aimed at this fake app hostname.
                if urlsplit(r.url).netloc!=host:
                    return route.abort()
                h=r.all_headers();h['host']=host
                res=adapter.handle(af.HttpRequest(r.method,r.url,headers=h,params={},
                                   route_params={},body=r.post_data_buffer or b''),None)
                route.fulfill(status=res.status_code,headers=dict(res.headers),body=res.get_body())

            def sign(page,name,pw):
                page.goto(origin)
                page.get_by_label('Username').fill(name)
                page.get_by_label('Password').fill(pw)
                page.get_by_role('button',name='Sign in').click()

            with patch.object(adapter,'runtime',return_value=app),sync_playwright() as playwright:
                options={'headless':True}
                if os.environ.get('CHROMIUM_EXECUTABLE'):
                    options['executable_path']=os.environ['CHROMIUM_EXECUTABLE']
                with playwright.chromium.launch(**options) as browser:
                    mobile=browser.new_page(viewport={'width':390,'height':844})
                    counsel=browser.new_page(viewport={'width':1100,'height':800})
                    for page in (mobile,counsel):
                        page.route('**/*',route_requests)
                    sign(mobile,'demo-witness',witness_pw)
                    expect(mobile.get_by_role('heading',name='Fictional observatory intake')).to_be_visible()
                    expect(mobile.get_by_text('Supporting documents are optional.',exact=False)).to_be_visible()
                    expect(mobile.locator('mark').filter(has_text='checkout log')).to_be_visible()
                    expect(mobile.get_by_text('Exact definition from the request:',exact=False).first).to_be_visible()
                    mobile.get_by_role('button',name='Requests for Admission (RFAs) (1)',exact=True).click()
                    mobile.get_by_label('How would you like to respond?').select_option('false_input')
                    mobile.get_by_role('button',name='Send this response',exact=True).click()
                    expect(mobile.get_by_text('Response received by your lawyer’s portal.')).to_be_visible()
                    expect(mobile.get_by_text('Submitted: Not true to the best of my knowledge')).to_be_visible()
                    self.assertTrue(mobile.evaluate('document.documentElement.scrollWidth <= innerWidth'))
                    sign(counsel,'test-counsel',counsel_pw)
                    counsel.get_by_role('button',name='Fictional observatory intake').click()
                    counsel.locator('summary').filter(has_text='Admission No. 1').click()
                    expect(counsel.get_by_text('Not true to the best of my knowledge',exact=True)).to_be_visible()
