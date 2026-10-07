from __future__ import annotations
from dataclasses import asdict
from typing import Any
from ..config import APP_NAME,APP_VERSION
from ..utils import redact_command


def infer_report_type(ctx):
    explicit = getattr(ctx, 'report_type', 'auto')
    if explicit != 'auto':
        return explicit
    target = str(getattr(ctx, 'target', '')).lower()
    web_url = str(getattr(ctx, 'web_url', '')).lower()
    if any(token in target for token in ('/api/', '/api?', '/graphql', '/swagger', '/openapi')) or any(token in web_url for token in ('/api/', '/api?', '/graphql', '/swagger', '/openapi')):
        return 'api'
    detected = getattr(ctx, 'target_kind', 'auto')
    if detected in {'network','web','api'}:
        return detected
    if target.startswith(('http://', 'https://')):
        return 'web'
    return 'network'


def build_report(ctx,results,started,ended,analysis,diff,actions,scan_id,qwen_result=None):
    report_type = infer_report_type(ctx)
    return {
        'meta':{'application':APP_NAME,'version':APP_VERSION,'scan_id':scan_id,'started_at':started,'ended_at':ended,'target':ctx.target,'host':ctx.host,'web_url':ctx.web_url,'mode':ctx.mode,'report_type':report_type,'scope_attested':ctx.scope_attested,'scope_file':str(ctx.scope_file) if ctx.scope_file else None,'client':ctx.client_name,'assessment':ctx.assessment_name,'adaptive_enabled':ctx.adaptive,'sqlmap_mode':ctx.sqlmap_mode,'qwen_gguf':str(ctx.qwen_gguf) if ctx.qwen_gguf else None},
        'attack_surface':analysis.get('attack_surface',{}),'evidence_graph':analysis.get('graph',{}),'findings':analysis.get('reportable_findings',[]),'not_reported':analysis.get('not_reported',[]),'all_candidates':analysis.get('findings',[]),'analysis_summary':analysis.get('summary',{}),'adaptive_decisions':[a.__dict__ for a in actions],'diff':diff,'passive_probe':analysis.get('passive_probe',{}),
        'results':[{**asdict(r),'command':redact_command(r.command)} for r in results], 'qwen':qwen_result or None,
    }
