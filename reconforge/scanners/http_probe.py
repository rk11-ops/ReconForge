from __future__ import annotations
import asyncio, re, ssl, urllib.error, urllib.request
from urllib.parse import urljoin, urlparse
from ..evidence.normalize import extract_body_markers, extract_technologies, redact_http_headers
from ..utils import dedupe_ordered

class PassiveHTTPProbe:
    def __init__(self,ctx): self.ctx=ctx
    async def run(self):
        return await asyncio.to_thread(self._run_sync)
    def _fetch(self,url):
        req=urllib.request.Request(url,headers={'User-Agent':'ReconForge/4.1 passive-recon'},method='GET')
        try:
            with urllib.request.urlopen(req,timeout=10) as r:
                h=dict(r.headers.items()); body=r.read(65536).decode('utf-8',errors='replace')
                base=r.geturl()
                links=[]
                for raw in re.findall(r'''(?:href|src|action)\s*=\s*[\"\']([^\"\']+)''',body,re.I):
                    absolute=urljoin(base,raw)
                    try:
                        if urlparse(absolute).hostname and urlparse(absolute).hostname.lower()==urlparse(base).hostname.lower(): links.append(absolute)
                    except Exception: pass
                return {'status':'completed','http_status':r.status,'final_url':base,'server':h.get('Server'),'content_type':h.get('Content-Type'),'headers':redact_http_headers(h),'technologies':sorted(set(extract_technologies(' '.join(h.values())+' '+body))),'body_markers':extract_body_markers(body),'discovered_links':sorted(set(links))[:500]}
        except urllib.error.HTTPError as e:
            h=dict(e.headers.items()) if e.headers else {}
            return {'status':'completed','http_status':e.code,'final_url':url,'server':h.get('Server'),'content_type':h.get('Content-Type'),'headers':redact_http_headers(h),'technologies':sorted(set(extract_technologies(' '.join(h.values())))),'body_markers':[]}
        except Exception as e: return {'status':'error','error':str(e)}
    def _run_sync(self):
        data=self._fetch(self.ctx.web_url)
        if self.ctx.passive_depth>=2:
            extras={}
            for suffix in ('/robots.txt','/sitemap.xml','/.well-known/security.txt'):
                item=self._fetch(self.ctx.web_url.rstrip('/')+suffix); extras[suffix]=item
            data['passive_resources']=extras
        return data
