from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime,timezone
from pathlib import Path
from typing import Any

class AssessmentState:
    def __init__(self,ctx,scan_id:str):
        self.ctx=ctx; self.scan_id=scan_id; self.created_at=datetime.now(timezone.utc).isoformat(); self.current_stage='boot'; self.events=[]; self.tool_results=[]; self.actions=[]; self.analysis={}; self.validation=[]
        self.path=ctx.output_dir/'state.json'
    def event(self,event:str,**data):
        self.events.append({'ts':datetime.now(timezone.utc).isoformat(),'event':event,**data}); self.save()
    def save(self):
        payload={'scan_id':self.scan_id,'created_at':self.created_at,'current_stage':self.current_stage,'events':self.events[-2000:],'tool_results':[asdict(x) for x in self.tool_results],'actions':self.actions[-500:],'analysis_summary':self.analysis.get('summary',{}),'validation':self.validation[-500:]}
        self.path.write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding='utf-8')
    def transition(self,stage:str,**meta):
        self.current_stage=stage; self.event('stage_transition',stage=stage,**meta)
