from __future__ import annotations
import re
from urllib.parse import urlparse
from typing import Any
from .rules import web_service_found,api_endpoint,parameterized,TECH_TAG_RULES
from ..models import AdaptiveAction

class AdaptiveDecisionEngine:
    @classmethod
    def decide(cls,ctx,analysis,completed_tools)->list[AdaptiveAction]:
        if not ctx.adaptive: return []
        p=analysis.get('attack_surface',{}); ports=p.get('ports',[]); tech={str(x).lower() for x in p.get('technologies',[])}; endpoints=[str(x) for x in p.get('endpoints',[])]
        actions=[]; seen=set()
        def add(a):
            key=(a.type,a.base_path,a.label,a.tags)
            if key not in seen and a.priority>=0: seen.add(key); actions.append(a)
        if web_service_found(ports):
            if 'nuclei' not in completed_tools: add(AdaptiveAction('nuclei','Web service discovered; run HTTP template checks.',90))
            if 'wapiti' not in completed_tools: add(AdaptiveAction('wapiti','Web service discovered; run black-box web checks.',80))
            if 'nikto' not in completed_tools: add(AdaptiveAction('nikto','Web service discovered; run server/configuration checks.',70))
        for tech_name,(tag,prio) in TECH_TAG_RULES.items():
            if any(tech_name in t for t in tech) and 'nuclei' in completed_tools:
                add(AdaptiveAction('nuclei',f'{tech_name} fingerprint detected; run focused {tag} templates.',prio,tags=(tag,),label=tag,budget_cost=2))
        for ep in endpoints:
            path=urlparse(ep).path or '/'
            if api_endpoint(path) and 'fuzzer' in completed_tools:
                add(AdaptiveAction('fuzzer',f'API-like endpoint discovered at {path}; enumerate within that path.',85,base_path=path,label='api',budget_cost=2))
            if parameterized(ep):
                add(AdaptiveAction('sqlmap','Parameterized endpoint discovered; bounded SQLMap validation is eligible when enabled.',95,base_path=path,label='sqlmap',budget_cost=3))
        actions.sort(key=lambda x:(-x.priority,x.type,x.base_path))
        budget=0; out=[]
        for a in actions:
            if budget+a.budget_cost>getattr(ctx,'adaptive_budget',8): continue
            budget+=a.budget_cost; out.append(a)
        return out
