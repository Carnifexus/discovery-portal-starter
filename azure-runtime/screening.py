"""Restrictive file intake policy. It never rewrites or renders the uploaded original."""
import hashlib, io, re, socket, struct, time, warnings, zipfile
from datetime import datetime, timezone
import logging
logging.getLogger("pypdf").setLevel(logging.CRITICAL)
from pathlib import PurePosixPath
from urllib.parse import unquote

MAX_BYTES = 12 * 1024 * 1024
ALLOWED = {'.pdf':'application/pdf', '.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
 '.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', '.jpg':'image/jpeg',
 '.jpeg':'image/jpeg', '.png':'image/png'}
class Rejected(ValueError): pass
class ScannerOffline(RuntimeError): pass

def filename(encoded):
    s=unquote(encoded, errors='strict')
    if not 1 <= len(s.encode('utf8')) <= 180 or s != s.strip() or s.startswith('.') or any(
        c in '/\\:' or ord(c)<32 or 127<=ord(c)<160 or 0x202a<=ord(c)<=0x202e or 0x2066<=ord(c)<=0x2069 for c in s):
        raise Rejected('invalid_filename')
    ext=PurePosixPath(s).suffix.lower()
    if ext not in ALLOWED: raise Rejected('unsupported_file_type')
    if re.search(r'\.(?:exe|cmd|bat|ps1|js|vbs|sh|scr|msi|com|dll|jar|lnk|html|svg|docm|xlsm)(?:\.|$)',s,re.I):
        raise Rejected('unsupported_file_type')
    return s,ext

def structural_check(data, ext):
    try:
        if ext == '.pdf':
            if not data.startswith(b'%PDF-') or not data.rstrip().endswith(b'%%EOF'):
                raise Rejected('invalid_pdf')
            from pypdf import PdfReader
            from pypdf.generic import DictionaryObject, ArrayObject, IndirectObject
            rd=PdfReader(io.BytesIO(data),strict=True)
            if rd.is_encrypted: raise Rejected('password_protected_file')
            deny={'/AA','/OpenAction','/JavaScript','/JS','/Launch','/EmbeddedFiles','/EF','/RichMedia','/XFA','/SubmitForm','/GoToR','/Sound','/Movie'}
            seen=set(); work=[(rd.trailer['/Root'],0)]; visited=0
            while work:
                v,depth=work.pop(); visited+=1
                if visited>80000 or depth>120: raise Rejected('complex_pdf')
                if isinstance(v,IndirectObject):
                    key=(v.idnum,v.generation)
                    if key in seen: continue
                    seen.add(key); work.append((v.get_object(),depth+1)); continue
                if isinstance(v,DictionaryObject):
                    if any(str(k) in deny or (isinstance(o,str) and o in deny) for k,o in v.items()):
                        raise Rejected('active_pdf_content')
                    work.extend((o,depth+1) for o in v.values())
                elif isinstance(v,ArrayObject): work.extend((o,depth+1) for o in v)
            if not 1<=len(rd.pages)<=1000: raise Rejected('invalid_pdf')
        elif ext in ('.docx','.xlsx'):
            if not data.startswith(b'PK\x03\x04'): raise Rejected('invalid_office_file')
            from xml.etree import ElementTree as ET
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos=z.infolist(); total=sum(f.file_size for f in infos)
                if not 1<=len(infos)<=800 or total>36*1024*1024:
                    raise Rejected('office_file_limit')
                names=[x.filename.casefold() for x in infos]
                main='word/document.xml' if ext=='.docx' else 'xl/workbook.xml'
                if len(names)!=len(set(names)) or not {'[content_types].xml','_rels/.rels',main}<=set(names):
                    raise Rejected('invalid_office_file')
                for f in infos:
                    n=f.filename.casefold(); parts=n.split('/')
                    if n.startswith('/') or '..' in parts or '\\' in n or ':' in n or f.flag_bits&1 or                         f.file_size>12*1024*1024 or f.file_size>200*max(1,f.compress_size) or                         any(p in parts for p in ('embeddings','activex','externallinks','customui')) or n.endswith(('.bin','.exe','.js','.html','.svg','.vbs')):
                        raise Rejected('unsupported_office_content')
                    if n.endswith(('.rels','.xml')):
                        b=z.read(f)
                        # Only UTF-8 XML; no DTD, entities or external relationships.
                        if b'\x00' in b or re.search(rb'<!\s*(?:DOCTYPE|ENTITY)',b,re.I):
                            raise Rejected('unsupported_office_content')
                        root=ET.fromstring(b.decode('utf-8-sig'))
                        if n==main:
                            expected=('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}document' if ext=='.docx'
                                else '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}workbook')
                            if root.tag!=expected:raise Rejected('invalid_office_file')
                        if n=='[content_types].xml' and root.tag!='{http://schemas.openxmlformats.org/package/2006/content-types}Types':
                            raise Rejected('invalid_office_file')
                        if n.endswith('.rels') and root.tag!='{http://schemas.openxmlformats.org/package/2006/relationships}Relationships':
                            raise Rejected('invalid_office_file')
                        for el in root.iter():
                            codes=' '.join(el.attrib.values()).casefold()
                            if 'macroenabled' in codes or el.attrib.get('TargetMode','').casefold()=='external':
                                raise Rejected('unsupported_office_content')
        else:
            from PIL import Image
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                with Image.open(io.BytesIO(data)) as im:
                    allowed='PNG' if ext=='.png' else 'JPEG'
                    if im.format!=allowed or im.width*im.height>24_000_000 or getattr(im,'n_frames',1)!=1:
                        raise Rejected('invalid_image')
                    im.verify()
    except Rejected: raise
    except Exception: raise Rejected('malformed_file') from None

class Clamd:
    """Use only a local Unix socket. No uploads to a third-party scanner."""
    def __init__(self,path):
        if not path.startswith('/'): raise ValueError('Absolute local socket path required')
        self.path=path
    def exchange(self, command, data=None):
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                sock.settimeout(8)
                sock.connect(self.path);sock.sendall(command)
                if data is not None:
                    for i in range(0,len(data),65536):
                        block=data[i:i+65536];sock.sendall(struct.pack('!I',len(block))+block)
                    sock.sendall(b'\x00\x00\x00\x00')
                reply=b''
                while b'\x00' not in reply and len(reply)<4096:
                    part=sock.recv(1024)
                    if not part:break
                    reply+=part
        except OSError:raise ScannerOffline('scanner_unavailable') from None
        return reply

    def require_fresh_database(self):
        # clamd is launched with LC_ALL=C and TZ=UTC. VERSION emits a ctime
        # timestamp without an offset, so both of those settings are required.
        banner=self.exchange(b'zVERSION\x00')
        m=re.fullmatch(rb'ClamAV [^/\x00\r\n]+/[0-9]+/([^\x00\r\n]{24})\x00',banner)
        if not m:raise ScannerOffline('scanner_unavailable')
        try:when=datetime.strptime(m[1].decode('ascii'),'%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc).timestamp()
        except (ValueError,UnicodeError):raise ScannerOffline('scanner_unavailable') from None
        age=time.time()-when
        if not -300<=age<=72*3600:raise ScannerOffline('scanner_unavailable')

    def scan(self,data):
        self.require_fresh_database()
        reply=self.exchange(b'zINSTREAM\x00',data)
        if reply==b'stream: OK\x00':return
        if re.fullmatch(rb'stream: [^\x00\r\n]{1,1000} FOUND\x00',reply):
            raise Rejected('unsafe_file')
        raise ScannerOffline('scanner_unavailable')

def declared_type(data,ext):
    if not 0<len(data)<=MAX_BYTES: raise Rejected('invalid_size')
    # Reject mismatched signatures; run the scanner before complex parsing.
    headers={'.pdf':b'%PDF-', '.docx':b'PK\x03\x04', '.xlsx':b'PK\x03\x04',
             '.png':b'\x89PNG\r\n\x1a\n', '.jpg':b'\xff\xd8\xff', '.jpeg':b'\xff\xd8\xff'}
    if not data.startswith(headers[ext]): raise Rejected('content_type_mismatch')
    return None

def screened(data,ext,scanner):
    declared_type(data,ext)
    scanner.scan(data)
    structural_check(data,ext)
    return hashlib.sha256(data).hexdigest()
