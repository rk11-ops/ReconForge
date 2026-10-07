from __future__ import annotations
import html, ipaddress, os, re, socket
from pathlib import Path
from urllib.parse import urlparse
from .config import DEFAULT_WORDLISTS

def valid_hostname(host:str)->bool:
    host=host.rstrip('.')
    if not host or len(host)>253: return False
    label_re=re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    return all(label_re.fullmatch(x) for x in host.split('.'))

def format_host_for_url(host:str)->str:
    try:
        ip=ipaddress.ip_address(host)
        return f"[{host}]" if ip.version==6 else host
    except ValueError: return host

def normalize_target(raw:str):
    value=raw.strip()
    if not value: raise ValueError("Target cannot be empty")
    if any(c in value for c in ('\x00','\r','\n')): raise ValueError("Target contains forbidden control characters")
    if re.fullmatch(r"\[[^\]]+\]\([^\)]+\)",value): raise ValueError("Target looks like a Markdown link; provide raw URL/host")
    if '://' in value:
        p=urlparse(value)
        if p.scheme not in {'http','https'}: raise ValueError("Only http:// and https:// are supported")
        if p.username or p.password: raise ValueError("Credentials in target URL are not allowed")
        if not p.hostname: raise ValueError("Target URL has no hostname")
        host=p.hostname
        try: ipaddress.ip_address(host)
        except ValueError:
            if not valid_hostname(host): raise ValueError(f"Invalid hostname: {host}")
        return p._replace(fragment='').geturl().rstrip('/'),host,p._replace(fragment='').geturl().rstrip('/')
    host=value
    try: ipaddress.ip_address(host)
    except ValueError:
        if not valid_hostname(host): raise ValueError(f"Invalid hostname: {host}")
    return host,host,f"http://{format_host_for_url(host)}"

def is_ip(host:str)->bool:
    try: ipaddress.ip_address(host); return True
    except ValueError: return False

def resolve_ips(host:str)->set[str]:
    try: return {item[4][0] for item in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)}
    except socket.gaierror: return set()

def load_scope_entries(path:Path|None)->list[str]:
    if not path: return []
    return [x.strip() for x in path.read_text(encoding='utf-8',errors='replace').splitlines() if x.strip() and not x.lstrip().startswith('#')]

def enforce_scope(target:str,host:str,path:Path|None)->None:
    if not path: return
    entries=load_scope_entries(path)
    if not entries: raise ValueError('Scope file is empty')
    h=host.lower().rstrip('.')
    resolved=resolve_ips(host) if not is_ip(host) else {host}
    for entry in entries:
        e=entry.lower().strip()
        if e.startswith(('http://','https://')): e=urlparse(e).hostname or ''
        if e.startswith('*.') and h.endswith(e[1:]): return
        try:
            net=ipaddress.ip_network(e,strict=False)
            if any(ipaddress.ip_address(ip) in net for ip in resolved): return
        except ValueError: pass
        if h==e: return
    raise PermissionError(f"Target {host} is outside the supplied scope")

def ensure_directory(path_value:str)->Path:
    p=Path(path_value).expanduser().resolve(); p.mkdir(parents=True,exist_ok=True); return p

def validate_existing_file(path_value:str|None,label:str):
    if path_value is None: return None
    p=Path(path_value).expanduser().resolve()
    if not p.is_file() or not os.access(p,os.R_OK): raise ValueError(f"{label} does not exist/readable: {p}")
    return p

def normalize_relative_path(path:str)->str:
    p='/' + path.strip().lstrip('/')
    parsed=urlparse(p)
    p=parsed.path or '/'
    if '..' in Path(p).parts: raise ValueError("Path cannot contain '..'")
    if any(c in p for c in ('\x00','\r','\n')): raise ValueError("Path contains control characters")
    return p if p=='/' else '/' + p.strip('/') + '/'

def sanitize_filename(v:str)->str:
    s=re.sub(r'[^A-Za-z0-9._-]+','_',v).strip('._')
    return s[:120] or 'item'

def read_tail(path:Path,size:int=6000)->str:
    try:
        data=path.read_bytes()[-size:]
        return data.decode('utf-8',errors='replace')
    except Exception: return ''

def dedupe_ordered(items):
    out=[]; seen=set()
    for x in items:
        if x not in seen: seen.add(x); out.append(x)
    return out

def validate_nmap_ports(v):
    if v is None: return None
    v=v.strip()
    if not v or len(v)>200 or not re.fullmatch(r'[0-9A-Za-z,:._/-]+',v) or any(c.isspace() for c in v): raise ValueError('Invalid --nmap-ports')
    return v

def normalize_nmap_scripts(values):
    out=[]
    for raw in values:
        for x in raw.split(','):
            x=x.strip()
            if not x: continue
            if len(x)>120 or not re.fullmatch(r'[A-Za-z0-9_.*/?+:-]+',x): raise ValueError(f'Invalid NSE script: {x}')
            out.append(x)
    return tuple(dedupe_ordered(out))

def validate_nmap_script_args(v):
    if v is None: return None
    v=v.strip()
    if not v or len(v)>1000 or any(c in v for c in '\x00\r\n'): raise ValueError('Invalid --nmap-script-args')
    return v

def validate_nmap_extra_args(values):
    blocked={'-oA','-oG','-oN','-oS','-oX','-iL','-iR','-iR0'}; shellchars=set(';|&<>`$()')
    out=[]
    for raw in values:
        raw=raw.strip()
        if not raw or len(raw)>200 or any(c in raw for c in '\x00\r\n') or any(c in raw for c in shellchars) or not raw.startswith('-'): raise ValueError(f'Unsafe --nmap-arg: {raw!r}')
        opt=raw.split('=',1)[0]
        if opt in blocked or opt.startswith('--stylesheet'): raise ValueError(f'Reserved Nmap option: {raw}')
        out.append(raw)
    return tuple(out)

def validate_tags(values):
    out=[]
    for raw in values:
        for x in raw.split(','):
            x=x.strip().lower()
            if x and (len(x)>64 or not re.fullmatch(r'[A-Za-z0-9_.:-]+',x)): raise ValueError(f'Invalid Nuclei tag: {x}')
            if x: out.append(x)
    return tuple(dedupe_ordered(out))

def target_is_public(host:str,web_url:str)->bool:
    try:
        ip=ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local)
    except ValueError:
        # DNS names are treated as externally addressable only if all A/AAAA answers are non-private.
        ips=resolve_ips(host)
        return bool(ips) and all(not ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip).is_loopback for ip in ips)


def redact_command(argv):
    out=[]
    sensitive_markers=("authorization","cookie=","token=","apikey=","api-key=","secret=")
    for token in argv:
        low=str(token).lower()
        out.append("<redacted>" if any(m in low for m in sensitive_markers) else str(token))
    return out



def detect_target_kind(raw: str, web_url: str | None = None) -> str:
    value = str(raw).strip().lower()
    candidate = str(web_url or raw).lower()
    if any(token in candidate for token in ('/api/', '/api?', '/graphql', '/swagger', '/openapi')):
        return 'api'
    if value.startswith(('http://', 'https://')):
        return 'web'
    return 'network'


def primary_web_url(host: str, ports: list[dict] | None, explicit: str | None = None) -> str | None:
    if explicit and str(explicit).startswith(('http://', 'https://')):
        return explicit.rstrip('/')
    ports = ports or []
    https_ports = {'443','444','8443','9443'}
    http_ports = {'80','81','88','8000','8008','8080','8081','8088','8888','9000','9080'}
    for p in ports:
        if not isinstance(p, dict) or str(p.get('state')) != 'open':
            continue
        port = str(p.get('port') or '')
        svc = str(p.get('service') or '').lower()
        if port in https_ports or svc in {'https','ssl/http'} or 'ssl' in svc or 'tls' in svc:
            return f'https://{format_host_for_url(host)}' if port == '443' else f'https://{format_host_for_url(host)}:{port}'
    for p in ports:
        if not isinstance(p, dict) or str(p.get('state')) != 'open':
            continue
        port = str(p.get('port') or '')
        svc = str(p.get('service') or '').lower()
        if port in http_ports or 'http' in svc:
            return f'http://{format_host_for_url(host)}' if port == '80' else f'http://{format_host_for_url(host)}:{port}'
    return None
