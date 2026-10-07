from __future__ import annotations
import argparse,asyncio,sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from .config import APP_NAME,APP_VERSION,DEFAULT_TIMEOUT,PROFILES,TESTSSL_REPO_URL
from .models import RunContext
from .utils import normalize_target,validate_existing_file,ensure_directory,enforce_scope,validate_nmap_ports,normalize_nmap_scripts,validate_nmap_script_args,validate_nmap_extra_args,validate_tags,detect_target_kind
from .nse import inventory_nse, inventory_summary, script_spec_for_mode
from .engine.orchestrator import run_assessment

console=Console()

def build_parser():
    p=argparse.ArgumentParser(prog='reconforge',description='ReconForge Advanced Recon Orchestrator')
    p.add_argument('target',nargs='?',help='Authorized URL, hostname or IP')
    p.add_argument('--interactive',action='store_true')
    p.add_argument('--mode',choices=tuple(PROFILES),default='advanced')
    p.add_argument('--authorized',action='store_true')
    p.add_argument('--scope')
    p.add_argument('--client'); p.add_argument('--assessment')
    p.add_argument('--output-dir',default='./reconforge-results')
    p.add_argument('--max-parallel',type=int,default=4); p.add_argument('--tool-timeout',type=int,default=DEFAULT_TIMEOUT)
    p.add_argument('--wordlist'); p.add_argument('--fuzzer',choices=('auto','ffuf','feroxbuster'),default='auto')
    p.add_argument('--web-url'); p.add_argument('--no-adaptive',action='store_true'); p.add_argument('--no-diff',action='store_true')
    p.add_argument('--dry-run',action='store_true',help='Show every planned command without starting scanner processes or network probes')
    p.add_argument('--report',choices=('yes','no'),default='yes')
    p.add_argument('--report-type',choices=('auto','web','network','api'),default='auto',help='Report template: web, network, or api; auto infers from target')
    p.add_argument('--testssl-path',help=f'Path to testssl.sh executable (official repo: {TESTSSL_REPO_URL})')
    p.add_argument('--passive-depth',type=int,choices=(1,2),default=2)
    p.add_argument('--nuclei-tag',action='append',default=[])
    p.add_argument('--sqlmap',choices=('off','auto','force'),default='auto')
    p.add_argument('--qwen-gguf',help='Local Qwen 4B GGUF file or ZIP containing a GGUF')
    p.add_argument('--qwen-bin',help='Path/name of llama-cli executable')
    n=p.add_argument_group('Nmap'); n.add_argument('--nmap-scan-type',choices=('S','T','U','A','W','M')); n.add_argument('--nmap-service',action='store_true'); n.add_argument('--nmap-os',action='store_true'); n.add_argument('--nmap-aggressive',action='store_true'); n.add_argument('--nmap-no-ping',action='store_true'); n.add_argument('--nmap-ports'); n.add_argument('--nmap-web-ports',action='store_true'); n.add_argument('--nmap-script',action='append',default=[]); n.add_argument('--nmap-script-args'); n.add_argument('--nmap-arg',action='append',default=[])
    return p

def make_context(args):
    if not args.target and not args.interactive:
        args.interactive = True
    if not 1<=args.max_parallel<=16: raise ValueError('--max-parallel must be 1..16')
    if args.tool_timeout<30: raise ValueError('--tool-timeout must be >=30')
    target_value=args.target
    if not target_value:
        args.interactive = True
        target_value=Prompt.ask('Target (URL / API / hostname / IP)')
    if not args.authorized:
        if sys.stdin.isatty() and Confirm.ask('Is this target explicitly authorized for assessment?',default=False):
            args.authorized=True
        else:
            raise PermissionError('Execution blocked: confirm authorization, or pass --authorized for a permitted target.')
    target,host,web=normalize_target(target_value)
    if args.web_url:
        _,wh,w=normalize_target(args.web_url)
        if wh.lower()!=host.lower(): raise ValueError('--web-url must use the same host')
        web=w
    scope=validate_existing_file(args.scope,'Scope file'); enforce_scope(target,host,scope)
    wordlist=validate_existing_file(args.wordlist,'Wordlist')
    out=ensure_directory(args.output_dir); history=out/'.history'; history.mkdir(parents=True,exist_ok=True)
    ports='80,443' if args.nmap_web_ports else validate_nmap_ports(args.nmap_ports)
    if args.nmap_web_ports and args.nmap_ports: raise ValueError('Use only one of --nmap-web-ports/--nmap-ports')
    qwen=validate_existing_file(args.qwen_gguf,'Qwen GGUF/ZIP') if args.qwen_gguf else None
    testssl_path=validate_existing_file(args.testssl_path,'testssl.sh') if args.testssl_path else None
    nmap_scripts=normalize_nmap_scripts(args.nmap_script) if args.nmap_script else (script_spec_for_mode(args.mode),)
    ctx=RunContext(target=target,host=host,web_url=web,target_kind=detect_target_kind(target, web),mode=args.mode,output_dir=out,history_root=history,tool_timeout=args.tool_timeout,max_parallel=args.max_parallel,fuzzer=args.fuzzer,custom_wordlist=wordlist,nmap_scan_type=args.nmap_scan_type,nmap_service_version=args.nmap_service,nmap_os_detection=args.nmap_os,nmap_aggressive=args.nmap_aggressive,nmap_no_ping=args.nmap_no_ping,nmap_ports=ports,nmap_scripts=nmap_scripts,nmap_script_args=validate_nmap_script_args(args.nmap_script_args),nmap_extra_args=validate_nmap_extra_args(args.nmap_arg),nuclei_tags=validate_tags(args.nuclei_tag),scope_attested=True,scope_file=scope,client_name=args.client,assessment_name=args.assessment,adaptive=not args.no_adaptive,diff_enabled=not args.no_diff,adaptive_budget=PROFILES[args.mode].adaptive_budget,sqlmap_mode=args.sqlmap,qwen_gguf=qwen,qwen_bin=args.qwen_bin,report_enabled=(args.report=='yes'),dry_run=args.dry_run,passive_depth=args.passive_depth,report_type=args.report_type,testssl_path=testssl_path)
    return ctx

def banner(): console.print(Panel.fit(f'[bold cyan]RECON[/bold cyan][bold white]FORGE[/bold white]  [dim]Advanced Recon CLI v{APP_VERSION}[/dim]',border_style='cyan'))

def preflight_tools():
    import shutil
    checks=[('nmap','nmap'),('nikto','nikto'),('wapiti','wapiti'),('nuclei','nuclei'),('sqlmap','sqlmap'),('ffuf','ffuf'),('feroxbuster','feroxbuster'),('testssl.sh','testssl.sh'),('llama-cli','llama-cli')]
    table=Table(title='Toolchain Preflight'); table.add_column('Tool'); table.add_column('Status')
    for label,exe in checks:
        table.add_row(label, 'READY' if shutil.which(exe) else 'NOT INSTALLED')
    console.print(table)
    console.print(inventory_summary(inventory_nse()))

def main():
    args=build_parser().parse_args();
    if not args.target:
        args.interactive=True
    banner()
    try:
        ctx=make_context(args)
        preflight_tools()
        console.print(Panel(f'Target: {ctx.target}\nDetected type: {ctx.target_kind}\nMode: {ctx.mode}\nReport type: {ctx.report_type}\nAdaptive: {ctx.adaptive}\nSQLMap: {ctx.sqlmap_mode}\nTestSSL: {ctx.testssl_path or "auto-discover"}\nQwen GGUF: {ctx.qwen_gguf or "off"}\nDry-run: {ctx.dry_run}',title='Preflight',border_style='blue'))
        if args.dry_run: console.print('[yellow]DRY-RUN: no scanner process and no passive network request will be started.[/yellow]')
        report,paths=asyncio.run(run_assessment(ctx,lambda s: console.print(f'[bold]{s}[/bold]')))
        table=Table(title='Final Summary'); table.add_column('Metric'); table.add_column('Value')
        table.add_row('Reportable findings',str(len(report.get('findings',[])))); table.add_row('Suppressed candidates',str(len(report.get('not_reported',[])))); table.add_row('Ports',str(len(report.get('attack_surface',{}).get('ports',[])))); table.add_row('Endpoints',str(len(report.get('attack_surface',{}).get('endpoints',[])))); table.add_row('JSON',str(paths['json']) if paths.get('json') else 'skipped'); table.add_row('HTML',str(paths.get('html')) if paths.get('html') else 'skipped'); console.print(table)
        return 0
    except KeyboardInterrupt: console.print('[yellow]Interrupted.[/yellow]'); return 130
    except (ValueError,PermissionError) as e: console.print(f'[red]Error:[/red] {e}'); return 2
    except Exception as e: console.print(f'[red]Fatal:[/red] {e}'); return 1
