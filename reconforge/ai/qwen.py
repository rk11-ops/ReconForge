from __future__ import annotations
import json, os, shutil, subprocess, tempfile, zipfile
from pathlib import Path
from ..utils import read_tail,sanitize_filename

MAX_PROMPT_CHARS=18000

def resolve_gguf(value:Path)->Path:
    value=value.expanduser().resolve()
    if value.suffix.lower()=='.gguf':
        if not value.is_file(): raise FileNotFoundError(f'Qwen GGUF not found: {value}')
        return value
    if value.suffix.lower()!='.zip': raise ValueError('--qwen-gguf must point to a .gguf or .zip containing a .gguf')
    if not value.is_file(): raise FileNotFoundError(f'Qwen model archive not found: {value}')
    dest=value.parent/f'.reconforge_qwen_{value.stem}'; dest.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(value) as z:
        names=[n for n in z.namelist() if n.lower().endswith('.gguf')]
        if not names: raise ValueError('Qwen ZIP contains no .gguf model')
        chosen=sorted(names,key=lambda n: (len(Path(n).parts),len(n)))[0]
        target=Path(chosen)
        if target.is_absolute() or '..' in target.parts: raise ValueError('Unsafe path inside Qwen ZIP')
        out=dest/target.name
        with z.open(chosen) as src, out.open('wb') as dst:
            while True:
                block=src.read(1024*1024)
                if not block: break
                dst.write(block)
    return out

def _prompt(analysis):
    payload={'summary':analysis.get('summary',{}),'attack_surface':analysis.get('attack_surface',{}),'findings':analysis.get('findings',[])[:30],'reportable_findings':analysis.get('reportable_findings',[])[:30],'not_reported':analysis.get('not_reported',[])[:30],'adaptive_decisions':analysis.get('adaptive_decisions',[])[:20],'diff':analysis.get('diff',{})}
    data=json.dumps(payload,ensure_ascii=False,sort_keys=True)[:MAX_PROMPT_CHARS]
    return ('You are the local Qwen triage layer for an authorized security assessment. '
            'Summarize only the supplied JSON. Do not invent vulnerabilities, facts, severity, exploitation, or validation. '
            'The deterministic ReconForge engine is authoritative. Return concise operator notes with sections: '
            'Attack Surface, Confirmed/Corroborated Findings, Suppressed Candidates, Next Review Items.\n\n'+data)

def run_qwen_gguf(ctx,analysis,console_print=print):
    try: model=resolve_gguf(Path(ctx.qwen_gguf))
    except Exception as e: return {'status':'error','reason':str(e)}
    binary=ctx.qwen_bin or shutil.which('llama-cli') or shutil.which('llama')
    if not binary: return {'status':'skipped','reason':'llama-cli/llama executable not found; install llama.cpp and add it to PATH.'}
    out=ctx.output_dir/'qwen-summary.txt'; log=ctx.output_dir/'logs'/'qwen-gguf.log'; prompt=_prompt(analysis)
    argv=[binary,'-m',str(model),'-n','512','-c','8192','-p',prompt]
    console_print(f'COMMAND > {" ".join(__import__("shlex").quote(x) for x in argv)}')
    try:
        proc=subprocess.run(argv,capture_output=True,text=True,timeout=min(ctx.tool_timeout,900),check=False)
        log.write_text((proc.stdout or '')+'\n--- STDERR ---\n'+(proc.stderr or ''),encoding='utf-8')
        out.write_text(proc.stdout or '',encoding='utf-8')
        return {'status':'completed' if proc.returncode==0 else 'failed','model':str(model),'binary':binary,'output_path':str(out),'log_path':str(log),'returncode':proc.returncode}
    except Exception as e: return {'status':'error','reason':str(e),'model':str(model),'binary':binary}
