"""Make an allowlisted Azure runtime ZIP with deterministic, deployable file permissions."""
import argparse
import os
from pathlib import Path
from zipfile import ZipFile,ZipInfo,ZIP_DEFLATED

FILES=('config.py','function_app.py','host.json','portal.py','quarantine.py','screening.py',
       'storage.py','requirements.txt','web/index.html','web/app.css','web/app.js')
ROOT=Path(__file__).resolve().parent

def build(out):
    for name in FILES:
        p=ROOT/name
        if not p.is_file() or p.resolve()!=p:
            raise ValueError("Expected regular allowlisted source file: "+name)
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f, ZipFile(f,'w') as z:
        for name in FILES:
            entry=ZipInfo(name)
            entry.create_system=3
            entry.external_attr=0o100644<<16
            entry.compress_type=ZIP_DEFLATED
            z.writestr(entry,(ROOT/name).read_bytes())

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('output',type=Path)
    build(ap.parse_args().output)
