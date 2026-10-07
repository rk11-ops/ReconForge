from __future__ import annotations
import socket, ssl
from urllib.parse import urlparse

def validate_tls(url):
    p=urlparse(url)
    if p.scheme!='https': return {'status':'not-applicable','reason':'Target URL is not HTTPS.','evidence':{}}
    host=p.hostname; port=p.port or 443
    try:
        ctx=ssl.create_default_context();
        with socket.create_connection((host,port),timeout=10) as raw:
            with ctx.wrap_socket(raw,server_hostname=host) as s:
                cipher=s.cipher(); version=s.version(); cert=s.getpeercert()
        weak=version in {'TLSv1','TLSv1.1'} or (cipher and any(x in cipher[0].upper() for x in ('RC4','3DES','NULL','EXPORT')))
        return {'status':'confirmed' if weak else 'not-reproduced','reason':('Weak TLS protocol/cipher reproduced.' if weak else 'No weak TLS protocol/cipher reproduced by the stdlib handshake.'),'evidence':{'protocol':version,'cipher':cipher,'subject':cert.get('subject'),'issuer':cert.get('issuer')}}
    except Exception as e:
        return {'status':'error','reason':f'TLS validation failed: {e}','evidence':{}}
