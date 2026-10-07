from __future__ import annotations
import json
from .base import BaseScanner
from ..config import PROFILES
class NucleiRunner(BaseScanner):
    name='nuclei'; executable='nuclei'
    def __init__(self,ctx,tags=()): super().__init__(ctx); self.tags=tuple(tags)
    def build_command(self):
        suffix='_adaptive' if self.tags else ''; artifact=self.ctx.output_dir/'artifacts'/f'nuclei{suffix}.jsonl'; p=PROFILES[self.ctx.mode]
        argv=['nuclei','-u',self.ctx.web_url,'-severity','low,medium,high,critical','-rate-limit',str(p.nuclei_rate),'-concurrency',str(p.nuclei_concurrency),'-jsonl-export',str(artifact),'-no-color']
        if self.tags: argv += ['-tags',','.join(self.tags)]
        return argv,artifact
    def enrich_result(self,result,artifact):
        if not artifact or not artifact.exists(): return
        findings=[]; errors=0
        for line in artifact.read_text(encoding='utf-8',errors='replace').splitlines():
            if not line.strip(): continue
            try:
                item=json.loads(line); info=item.get('info',{}) if isinstance(item,dict) else {}
                findings.append({'template_id':item.get('template-id') or item.get('templateID'),'name':info.get('name'),'severity':info.get('severity'),'type':item.get('type'),'host':item.get('host'),'matched_at':item.get('matched-at') or item.get('matchedAt'),'tags':info.get('tags') or [],'curl_command':item.get('curl-command')})
            except json.JSONDecodeError: errors += 1
        sev={}
        for f in findings: sev[str(f.get('severity') or 'unknown').lower()]=sev.get(str(f.get('severity') or 'unknown').lower(),0)+1
        result.summary={'finding_count':len(findings),'severity_counts':sev,'parse_errors':errors,'findings':findings[:1000],'tags':list(self.tags)}
