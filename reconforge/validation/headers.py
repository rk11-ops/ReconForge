from __future__ import annotations
import re
import urllib.error, urllib.request
from ..evidence.normalize import redact_http_headers

SECURITY_HEADERS=('content-security-policy','x-frame-options','referrer-policy','permissions-policy','strict-transport-security')

def fetch(url,timeout=10):
    req=urllib.request.Request(url,headers={'User-Agent':'ReconForge/4.1 validator'},method='GET')
    try:
        with urllib.request.urlopen(req,timeout=timeout) as r:
            return {'status':r.status,'url':r.geturl(),'headers':dict(r.headers.items()),'body':r.read(32768).decode('utf-8',errors='replace')}
    except urllib.error.HTTPError as e:
        return {'status':e.code,'url':url,'headers':dict(e.headers.items()) if e.headers else {},'body':''}
    except Exception as e:
        return {'error':str(e),'headers':{},'body':''}

def validate_security_headers(url):
    r=fetch(url); h={k.lower():v for k,v in r.get('headers',{}).items()}
    missing=[x for x in SECURITY_HEADERS if x not in h]
    return {'status':'confirmed' if missing else 'not-reproduced','reason':('Response is missing one or more security headers.' if missing else 'Expected security headers are present.'),'evidence':{'http_status':r.get('status'),'missing':missing,'headers':redact_http_headers(r.get('headers',{}))}}

def validate_clickjacking(url):
    r=fetch(url); h={k.lower():v for k,v in r.get('headers',{}).items()}; csp=h.get('content-security-policy','')
    protected=bool(h.get('x-frame-options')) or bool(re.search(r'frame-ancestors\s+[^;]+',csp,re.I))
    return {'status':'not-reproduced' if protected else 'confirmed','reason':('Clickjacking protection is present.' if protected else 'Neither X-Frame-Options nor CSP frame-ancestors protection was reproduced.'),'evidence':{'http_status':r.get('status'),'x_frame_options':h.get('x-frame-options'),'frame_ancestors':re.findall(r'frame-ancestors\s+([^;]+)',csp,re.I)}}


def validate_missing_csp(url):
    r=fetch(url); h={k.lower():v for k,v in r.get("headers",{}).items()}
    csp=h.get("content-security-policy")
    return {"status":"confirmed" if not csp else "not-reproduced","reason":("Content-Security-Policy is absent on the validation response." if not csp else "Content-Security-Policy is present."),"evidence":{"http_status":r.get("status"),"content_security_policy":csp}}

def validate_cors(url):
    r=fetch(url); h={k.lower():v for k,v in r.get("headers",{}).items()}; acao=h.get("access-control-allow-origin","")
    weak=acao.strip()=="*"
    return {"status":"confirmed" if weak else "not-reproduced","reason":("Access-Control-Allow-Origin: * reproduced." if weak else "Wildcard CORS was not reproduced."),"evidence":{"http_status":r.get("status"),"access_control_allow_origin":acao}}

def validate_verbose_errors(url):
    r=fetch(url); body=r.get("body",""); import re
    hit=bool(re.search(r"(Traceback|Stack trace|NullPointerException|SQLSTATE|Fatal error|DEBUG = True)",body,re.I))
    return {"status":"confirmed" if hit else "not-reproduced","reason":("Verbose error/debug marker reproduced in response body." if hit else "No known verbose-error marker reproduced."),"evidence":{"http_status":r.get("status"),"marker_reproduced":hit}}

def validate_directory_listing(url):
    r=fetch(url); body=r.get("body",""); import re
    hit=bool(re.search(r"<title>\s*Index of /|Directory listing for /",body,re.I))
    return {"status":"confirmed" if hit else "not-reproduced","reason":("Directory-listing marker reproduced." if hit else "Directory-listing marker not reproduced."),"evidence":{"http_status":r.get("status"),"marker_reproduced":hit}}
