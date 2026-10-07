from __future__ import annotations
from .headers import fetch

def validate_cookie_flags(url):
    r=fetch(url); raw=[]
    for k,v in r.get('headers',{}).items():
        if k.lower()=='set-cookie': raw.append(v)
    # urllib collapses repeated Set-Cookie on some servers; still useful as a lightweight check.
    weak=[]
    for cookie in raw:
        low=cookie.lower()
        missing=[]
        if 'secure' not in low: missing.append('Secure')
        if 'httponly' not in low: missing.append('HttpOnly')
        if 'samesite' not in low: missing.append('SameSite')
        if missing: weak.append({'cookie':cookie.split(';',1)[0],'missing':missing})
    return {'status':'confirmed' if weak else 'not-reproduced','reason':('At least one observed Set-Cookie header lacks common hardening attributes.' if weak else 'No weak cookie flag reproduced on the validation response.'),'evidence':{'cookies':weak,'http_status':r.get('status')}}
