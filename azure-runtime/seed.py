"""Build a fresh encrypted seed offline; no existing state or cloud credentials are required."""
import argparse
import getpass
import json
import os
import tempfile
from pathlib import Path
from config import deployment_host
from portal import USER,configured_key,validpass
from quarantine import QuarantinePortal
from storage import SnapshotApp

SAMPLE=Path(__file__).with_name('fictional-import-example.json')
DEMO_USERS=('demo-witness','demo-custodian')

def write_seed(out,origin,key,token,username,password,fictional_passwords=None):
    deployment_host(origin)
    if not USER.fullmatch(username) or not validpass(password):
        raise ValueError('Require a valid counsel username and a strong password')
    if fictional_passwords is not None and ({*fictional_passwords}!=set(DEMO_USERS)
            or username in DEMO_USERS or any(not validpass(p) for p in fictional_passwords.values())
            or len({password,*fictional_passwords.values()})!=3):
        raise ValueError('Use separate sample identities and distinct long passwords')
    with tempfile.TemporaryDirectory() as t:
        db=Path(t)/'state.sqlite'
        p=QuarantinePortal(db,key,origin,None,token,init=True)
        with p.tx(True) as c:
            p.register(c,username,password,'counsel',None)
            if fictional_passwords is not None:
                mid=p.create_matter(c,'Fictional observatory intake')
                c.execute('INSERT INTO discovery_access VALUES(?)',(mid,))
                people={name:p.register(c,name,pw,'client',mid) for name,pw in fictional_passwords.items()}
                for item in json.loads(SAMPLE.read_text(encoding='utf-8')):
                    r=p.add_request(c,mid,item['title'],item['details'],item['kind'],
                                    item.get('definitions',[]),item['category'])
                    who='demo-custodian' if item['category']=='rpd' else 'demo-witness'
                    c.execute('INSERT INTO assignment VALUES(?,?,?)',(r,r,people[who]))
        wrapped=SnapshotApp(None,None,key,origin,token).seal(db.read_bytes())
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(wrapped)

def confirmed(prompt):
    pw=getpass.getpass(prompt)
    if not validpass(pw) or pw!=getpass.getpass('Confirm password: '):
        raise ValueError('Passwords must match and be at least 16 characters')
    return pw

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--username',required=True)
    a.add_argument('--origin',required=True)
    a.add_argument('--out',type=Path,required=True)
    a.add_argument('--fictional-sample',action='store_true',help='Add the bundled three-item fictional sample')
    args=a.parse_args()
    os.umask(0o077)
    try:
        deployment_host(args.origin)
        if not USER.fullmatch(args.username.lower()):
            raise ValueError('Use a valid lowercase counsel username')
        key=configured_key(); token=os.environ['INTAKE_V2_WORKER_TOKEN']
        password=confirmed('New counsel password: ')
        sample={n:confirmed('Separate password for '+n+': ') for n in DEMO_USERS} if args.fictional_sample else None
        write_seed(args.out,args.origin,key,token,args.username.lower(),password,sample)
    except (KeyError,ValueError,FileExistsError) as ex:
        a.error(str(ex))

if __name__=='__main__':
    main()
