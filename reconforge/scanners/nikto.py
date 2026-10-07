from __future__ import annotations
from .base import BaseScanner
from ..config import PROFILES
from ..evidence.normalize import infer_severity
class NiktoRunner(BaseScanner):
    name='nikto'; executable='nikto'
    def build_command(self):
        artifact=self.ctx.output_dir/'artifacts'/'nikto.txt'; argv=['nikto','-host',self.ctx.web_url,'-output',str(artifact),'-Format','txt','-nolookup','-timeout','10']
        tuning=PROFILES[self.ctx.mode].nikto_tuning
        if tuning: argv += ['-Tuning',tuning]
        return argv,artifact
    def enrich_result(self,result,artifact):
        if not artifact or not artifact.exists(): return
        obs=[x[1:].strip() for x in artifact.read_text(encoding='utf-8',errors='replace').splitlines() if x.strip().startswith('+')]
        result.summary={'observation_count':len(obs),'observations':obs[:1000],'severity_counts':{s:sum(1 for o in obs if infer_severity(o)==s) for s in ('critical','high','medium','low','info')}}
