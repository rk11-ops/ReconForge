from __future__ import annotations
import re, json
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from .base import BaseScanner
from ..config import PROFILES

DANGEROUS_FLAGS={'--dump','--dump-all','--os-shell','--sql-shell','--file-read','--file-write','--os-pwn','--priv-esc','--msf-path'}

class SQLMapRunner(BaseScanner):
    name='sqlmap'; executable='sqlmap'
    def __init__(self,ctx,url): super().__init__(ctx); self.url=url
    def build_command(self):
        p=PROFILES[self.ctx.mode]; artifact=self.ctx.output_dir/'artifacts'/'sqlmap'; artifact.mkdir(parents=True,exist_ok=True)
        argv=['sqlmap','-u',self.url,'--batch','--smart','--level',str(min(p.sqlmap_level,2)),'--risk',str(min(p.sqlmap_risk,1)),'--output-dir',str(artifact),'--flush-session','--disable-coloring']
        if self.ctx.mode in {'deep','advanced'}: argv += ['--forms', '--crawl',str(min(p.sqlmap_crawl,2))]
        if any(x in self.url for x in ('?','&')): argv += ['--skip-heuristics']
        assert not (DANGEROUS_FLAGS & set(argv))
        return argv,artifact
    def enrich_result(self,result,artifact):
        findings=[]; text=''
        if result.stdout_path:
            try: text=open(result.stdout_path,encoding='utf-8',errors='replace').read()
            except Exception: text=''
        signals=re.findall(r'(?:is vulnerable|is injectable|Type:|Parameter:)',text,re.I)
        if signals:
            findings.append({'name':'SQL injection candidate','severity':'high','matched_at':self.url,'evidence':'SQLMap detection signal','signal_count':len(signals)})
        result.summary={'detection_signals':len(signals),'findings':findings,'url':self.url,'mode':self.ctx.mode}
