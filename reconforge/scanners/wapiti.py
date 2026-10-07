from __future__ import annotations
import json
from .base import BaseScanner
from ..config import PROFILES

def map_wapiti_level(level):
    try: n=int(level)
    except (TypeError,ValueError): return 'unknown'
    return {0:'info',1:'low',2:'medium',3:'high',4:'critical'}.get(n,'unknown')

def summarize_wapiti(data):
    if not isinstance(data,dict): return {'format':'unknown'}
    rec=[]
    for key in ('vulnerabilities','anomalies','warnings'):
        value=data.get(key)
        if isinstance(value,dict):
            for category,entries in value.items():
                if isinstance(entries,list):
                    for entry in entries:
                        if isinstance(entry,dict): rec.append({'category':category,'name':category,'parameter':entry.get('parameter'),'path':entry.get('path'),'level':entry.get('level'),'severity':map_wapiti_level(entry.get('level')),'info':entry.get('info') or entry.get('description')})
        elif isinstance(value,list): rec.extend(x for x in value if isinstance(x,dict))
    return {'finding_count':len(rec),'findings':rec[:1000]}

class WapitiRunner(BaseScanner):
    name='wapiti'; executable='wapiti'
    def build_command(self):
        artifact=self.ctx.output_dir/'artifacts'/'wapiti.json'; argv=['wapiti','-u',self.ctx.web_url,'-f','json','-o',str(artifact),'--scope','folder']
        level=PROFILES[self.ctx.mode].wapiti_level
        if level is not None: argv += ['-l',str(level)]
        return argv,artifact
    def enrich_result(self,result,artifact):
        if not artifact or not artifact.exists(): return
        try: result.summary=summarize_wapiti(json.loads(artifact.read_text(encoding='utf-8',errors='replace')))
        except Exception as exc: result.notes.append(f'Could not parse Wapiti JSON: {exc}')
