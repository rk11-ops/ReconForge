from __future__ import annotations
import json
from datetime import datetime,timezone
from pathlib import Path
from ..utils import sanitize_filename,ensure_directory,normalize_target,enforce_scope,validate_existing_file

def create_run(ctx):
    scan_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    ctx.output_dir=(ctx.output_dir/f'{sanitize_filename(ctx.host)}-{ctx.mode}-{scan_id}').resolve(); ctx.output_dir.mkdir(parents=True,exist_ok=True)
    for d in ('artifacts','logs','commands','evidence'): (ctx.output_dir/d).mkdir(exist_ok=True)
    ctx.state_file=ctx.output_dir/'state.json'
    return scan_id

def load_latest_snapshot(root:Path,host:str):
    p=root/'latest'/f'{sanitize_filename(host)}.json'
    if not p.exists(): return None
    try: return json.loads(p.read_text(encoding='utf-8'))
    except Exception: return None

def save_latest_snapshot(root:Path,host:str,snapshot,scan_id):
    p=root/'latest'; p.mkdir(parents=True,exist_ok=True); out=p/f'{sanitize_filename(host)}.json'; out.write_text(json.dumps({'scan_id':scan_id,'snapshot':snapshot},indent=2),encoding='utf-8'); return out

def make_snapshot(analysis):
    s=analysis.get('attack_surface',{}); findings=analysis.get('findings',[])
    return {'ports':sorted(f"{p.get('protocol','tcp')}:{p.get('port')}:{p.get('service','')}" for p in s.get('ports',[]) if p.get('port')),'technologies':sorted(s.get('technologies',[])),'endpoints':sorted(s.get('endpoints',[])),'findings':sorted(f.get('fingerprint','') for f in findings)}

def snapshot_diff(previous,current):
    old=previous.get('snapshot',previous) if previous else {}
    added={}; removed={}
    for key in ('ports','technologies','endpoints','findings'):
        a=set(old.get(key,[])); b=set(current.get(key,[])); added[key]=sorted(b-a); removed[key]=sorted(a-b)
    return {'baseline_present':bool(previous),'added':added,'removed':removed}
