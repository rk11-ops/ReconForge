from __future__ import annotations
import asyncio
from datetime import datetime,timezone
from typing import Any
from ..config import PROFILES
from ..models import AdaptiveAction
from ..scanners import NmapScanner,NiktoRunner,WapitiRunner,NucleiRunner,FuzzerEngine,SQLMapRunner,TestSSLRunner
from ..scanners.http_probe import PassiveHTTPProbe
from ..evidence.engine import EvidenceEngine
from ..adaptive.decision_engine import AdaptiveDecisionEngine
from ..adaptive.rules import web_service_found
from ..utils import primary_web_url, detect_target_kind, format_host_for_url
from ..validation.findings import validate_findings
from ..engine.scheduler import execute_sequential
from ..engine.state import AssessmentState
from ..engine.lifecycle import create_run,load_latest_snapshot,save_latest_snapshot,make_snapshot,snapshot_diff
from ..reporting.builder import build_report
from ..reporting.html import write_reports
from ..ai.qwen import run_qwen_gguf

FIREWALL_HINTS = (
    'firewall',
    'intrusion',
    ' ids',
    'ips ',
    'rate limit',
    'too many',
    'host seems down',
    'packet dropped',
    'admin prohibited',
    'waf',
)

def firewall_or_ids_suspected(results) -> bool:
    nmap_results = [r for r in results if r.tool == 'nmap']
    for result in nmap_results:
        summary = result.summary if isinstance(result.summary, dict) else {}
        if float(summary.get('filtered_ratio') or 0) >= 0.60:
            return True
        blob = ' '.join(
            [
                str(result.stdout_tail or ''),
                str(result.stderr_tail or ''),
                ' '.join(str(x) for x in (result.notes or [])),
            ]
        ).lower()
        if any(token in blob for token in FIREWALL_HINTS):
            return True
    return False

def fallback_web_url(host: str) -> list[str]:
    formatted = format_host_for_url(host)
    return [f'https://{formatted}', f'http://{formatted}']


def tls_target_from_analysis(ctx, analysis):
    if str(ctx.web_url).lower().startswith('https://'):
        return ctx.web_url
    ports = analysis.get('attack_surface',{}).get('ports',[]) if isinstance(analysis,dict) else []
    for item in ports:
        if not isinstance(item,dict) or str(item.get('state')) != 'open':
            continue
        port=str(item.get('port') or '')
        service=str(item.get('service') or '').lower()
        if port in {'443','444','465','636','853','993','995','8443','9443'} or service in {'https','ssl/http','imaps','pop3s','ldaps'} or 'ssl' in service or 'tls' in service:
            return f'{ctx.host}:{port}'
    return None

def build_scanners(ctx,stage='initial',analysis=None):
    if stage=='recon': return [NmapScanner(ctx)]
    if stage=='web':
        out=[]
        # Visible fixed order: server checks -> TLS -> web vuln -> templates -> content discovery.
        out.append(NiktoRunner(ctx))
        tls_target = tls_target_from_analysis(ctx, analysis or {})
        if tls_target:
            out.append(TestSSLRunner(ctx, target=tls_target))
        out.append(WapitiRunner(ctx)); out.append(NucleiRunner(ctx,tags=ctx.nuclei_tags)); out.append(FuzzerEngine(ctx)); return out
    return []

def scanners_for_actions(ctx,actions):
    out=[]
    for a in actions:
        if a.type=='nuclei': out.append(NucleiRunner(ctx,tags=a.tags))
        elif a.type=='wapiti': out.append(WapitiRunner(ctx))
        elif a.type=='nikto': out.append(NiktoRunner(ctx))
        elif a.type=='fuzzer': out.append(FuzzerEngine(ctx,base_path=a.base_path,label=a.label))
    return out

def sqlmap_candidate_urls(analysis):
    urls=[]
    for ep in analysis.get('attack_surface',{}).get('endpoints',[]):
        if '?' in str(ep): urls.append(str(ep))
    return urls[:3]

async def run_assessment(ctx,console_print=print):
    scan_id=create_run(ctx); state=AssessmentState(ctx,scan_id); state.transition('preflight')
    start=datetime.now(timezone.utc).isoformat()
    ctx.__dict__['adaptive_budget']=PROFILES[ctx.mode].adaptive_budget
    console_print('\n=== STAGE 1/6 • RECON DISCOVERY ===')
    state.transition('recon')
    passive={'status':'dry-run'} if ctx.dry_run else {}
    recon_scanners=build_scanners(ctx,'recon'); results=await execute_sequential(recon_scanners,'recon',state)
    analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()
    console_print(f'TARGET > initial classification: {ctx.target_kind}')

    # Auto-detect web/API exposure after network discovery.
    explicit_web = str(ctx.target).lower().startswith(('http://','https://'))
    auto_web=primary_web_url(ctx.host, analysis.get('attack_surface',{}).get('ports',[]), ctx.web_url if explicit_web else None)
    if auto_web:
        ctx.web_url=auto_web
        ctx.target_kind=detect_target_kind(ctx.target, auto_web)
        console_print(f'TARGET > web surface discovered: {ctx.web_url} ({ctx.target_kind})')
        passive={'status':'dry-run'} if ctx.dry_run else await PassiveHTTPProbe(ctx).run()
        analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()

    # Heavy filtering/IDS gets a slower -T3 retry plus Nmap -A, not a firewall bypass.
    if ctx.dry_run or firewall_or_ids_suspected(results):
        if ctx.dry_run:
            console_print('ADAPTIVE PREVIEW > If filtering/IDS is detected, ReconForge retries at -T3 with -A.')
        else:
            console_print('ADAPTIVE > Firewall/IDS/filtering suspected from Nmap; retrying discovery at -T3 with aggressive (-A) scan.')
        retry=NmapScanner(ctx,timing_override=3,artifact_suffix='-t3-retry',force_aggressive=True)
        if ctx.dry_run:
            preview,_=retry.build_command()
            console_print('COMMAND > ' + retry.command_text(preview))
        else:
            results.extend(await execute_sequential([retry],'recon-retry',state))
            analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()
            auto_web=primary_web_url(ctx.host, analysis.get('attack_surface',{}).get('ports',[]), ctx.web_url if explicit_web else None)
            if auto_web:
                ctx.web_url=auto_web
                ctx.target_kind=detect_target_kind(ctx.target, auto_web)

    if not auto_web:
        probe=PassiveHTTPProbe(ctx)
        for candidate in fallback_web_url(ctx.host):
            if ctx.dry_run:
                auto_web=candidate
                ctx.web_url=candidate
                ctx.target_kind=detect_target_kind(ctx.target, candidate)
                console_print(f'TARGET > no open web ports yet; will still validate HTTP/TLS surface at {candidate}')
                break
            hit=probe._fetch(candidate)
            if hit.get('status')=='completed' and hit.get('http_status'):
                auto_web=candidate
                ctx.web_url=candidate
                ctx.target_kind=detect_target_kind(ctx.target, candidate)
                console_print(f'TARGET > HTTP/TLS responded at {candidate}; enabling nikto/testssl/wapiti')
                passive=hit
                analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()
                break

    console_print('\n=== STAGE 2/6 • WEB VALIDATION ===')
    state.transition('web')
    web_scanners=build_scanners(ctx,'web',analysis) if auto_web or ctx.dry_run else []
    web_results=await execute_sequential(web_scanners,'web',state)
    results.extend(web_results); analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()

    console_print('\n=== STAGE 3/6 • ADAPTIVE FOLLOW-UP ===')
    state.transition('adaptive')
    completed={r.tool for r in results if r.status in {'completed','dry-run'}}
    actions=AdaptiveDecisionEngine.decide(ctx,analysis,completed); state.actions.extend([a.__dict__ for a in actions]); state.save()
    for a in actions: console_print(f'ADAPTIVE > [{a.priority}] {a.type}: {a.reason}')
    adaptive_results=await execute_sequential(scanners_for_actions(ctx,actions),'adaptive',state)
    results.extend(adaptive_results); analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()

    console_print('\n=== STAGE 4/6 • SAFE VALIDATION + PoC GATE ===')
    state.transition('validate')
    # SQLMap runs before the final validation pass so its evidence participates in correlation.
    if ctx.sqlmap_mode!='off':
        candidates=sqlmap_candidate_urls(analysis)
        if ctx.sqlmap_mode=='force' or candidates:
            for url in (candidates[:2] if candidates else [ctx.web_url]):
                if 'sqlmap' in {r.tool for r in results} and ctx.sqlmap_mode!='force': break
                results.extend(await execute_sequential([SQLMapRunner(ctx,url)],'sqlmap',state))
            analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis
    validations=validate_findings(ctx,analysis); state.validation=validations; state.save()
    for f in analysis.get('findings',[]):
        v=next((x for x in validations if x['fingerprint']==f['fingerprint']),None)
        if v: f.update(v)

    console_print('\n=== STAGE 5/6 • QUALITY GATE + CORRELATION ===')
    state.transition('quality-gate')
    reportable=[]; not_reported=[]
    for f in analysis.get('findings',[]):
        status=f.get('validation_status','unverified')
        if status in {'confirmed','corroborated'}: reportable.append(f)
        else:
            not_reported.append({'candidate':f.get('name'),'severity':f.get('severity'),'status':status,'reason':f.get('validation_reason') or 'Insufficient independent evidence'})
    analysis['reportable_findings']=reportable; analysis['not_reported']=not_reported

    diff={'disabled':True}
    if ctx.diff_enabled:
        snap=make_snapshot(analysis); previous=load_latest_snapshot(ctx.history_root,ctx.host); diff=snapshot_diff(previous,snap); save_latest_snapshot(ctx.history_root,ctx.host,snap,scan_id)
        state.event('diff',added=diff.get('added',{}),removed=diff.get('removed',{}))

    console_print('\n=== STAGE 6/6 • REPORTING ===')
    state.transition('report')
    end=datetime.now(timezone.utc).isoformat()
    qwen_result=None
    if ctx.qwen_gguf:
        qwen_result=run_qwen_gguf(ctx,analysis,console_print)
    report=build_report(ctx,results,start,end,analysis,diff,actions,scan_id,qwen_result)
    paths=write_reports(report,ctx.output_dir,html_enabled=ctx.report_enabled) if ctx.report_enabled else {}
    state.transition('complete',report=str(paths.get('json')) if paths else 'reports-skipped')
    return report,paths
