from __future__ import annotations
import asyncio, os, shutil, signal, time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from ..models import ToolResult
from ..utils import read_tail

class BaseScanner(ABC):
    name='base'; executable=None
    def __init__(self,ctx): self.ctx=ctx
    def available(self): return bool(self.executable and shutil.which(self.executable))
    @abstractmethod
    def build_command(self): ...
    def command_text(self,argv): return ' '.join(shlex_quote(str(x)) for x in argv)
    async def run(self)->ToolResult:
        started=time.monotonic(); started_iso=datetime.now(timezone.utc).isoformat()
        phase_tag=getattr(self,'phase','unknown')
        stdout=self.ctx.output_dir/'logs'/f'{phase_tag}_{self.name}.stdout.log'; stderr=self.ctx.output_dir/'logs'/f'{phase_tag}_{self.name}.stderr.log'
        stdout.parent.mkdir(parents=True,exist_ok=True)
        try:
            argv,artifact=self.build_command()
        except Exception as exc:
            return ToolResult(tool=self.name,status='failed',duration_seconds=time.monotonic()-started,notes=[f'Command build failed: {exc}'],phase=getattr(self,'phase','unknown'),started_at=started_iso,ended_at=datetime.now(timezone.utc).isoformat())
        command_line=self.command_text(argv)
        cmd_path=self.ctx.output_dir/'commands'/f'{getattr(self,"phase","unknown")}_{self.name}_{int(time.time()*1000)}.cmd'
        cmd_path.parent.mkdir(parents=True,exist_ok=True)
        try: cmd_path.write_text(command_line+'\n',encoding='utf-8')
        except Exception: pass
        print(f'COMMAND > {command_line}', flush=True)
        if self.ctx.dry_run:
            available=self.available()
            note='Dry-run: process not started.' if available else f'Dry-run: executable not installed ({self.executable}).'
            return ToolResult(tool=self.name,status='dry-run',command=argv,artifacts=[str(artifact)] if artifact else [],duration_seconds=time.monotonic()-started,notes=[note],phase=getattr(self,'phase','unknown'),started_at=started_iso,ended_at=datetime.now(timezone.utc).isoformat())
        if not self.available():
            return ToolResult(tool=self.name,status='skipped',command=argv,artifacts=[str(artifact)] if artifact else [],duration_seconds=time.monotonic()-started,notes=[f'Executable not found: {self.executable}'],phase=getattr(self,'phase','unknown'),started_at=started_iso,ended_at=datetime.now(timezone.utc).isoformat())
        try:
            with stdout.open('wb') as out, stderr.open('wb') as err:
                proc=await asyncio.create_subprocess_exec(*argv,stdout=out,stderr=err,start_new_session=True)
                try: rc=await asyncio.wait_for(proc.wait(),timeout=self.ctx.tool_timeout)
                except asyncio.TimeoutError:
                    await terminate_process_group(proc)
                    return ToolResult(tool=self.name,status='timeout',command=argv,stdout_path=str(stdout),stderr_path=str(stderr),artifacts=[str(artifact)] if artifact else [],duration_seconds=time.monotonic()-started,stdout_tail=read_tail(stdout),stderr_tail=read_tail(stderr),notes=[f'Timeout after {self.ctx.tool_timeout}s'],phase=getattr(self,'phase','unknown'),started_at=started_iso,ended_at=datetime.now(timezone.utc).isoformat())
            result=ToolResult(tool=self.name,status='completed' if rc==0 else 'failed',returncode=rc,command=argv,stdout_path=str(stdout),stderr_path=str(stderr),artifacts=[str(artifact)] if artifact else [],duration_seconds=time.monotonic()-started,stdout_tail=read_tail(stdout),stderr_tail=read_tail(stderr),phase=getattr(self,'phase','unknown'),started_at=started_iso,ended_at=datetime.now(timezone.utc).isoformat())
            self.enrich_result(result,artifact); return result
        except Exception as exc:
            return ToolResult(tool=self.name,status='failed',command=argv,stdout_path=str(stdout),stderr_path=str(stderr),duration_seconds=time.monotonic()-started,notes=[f'Execution error: {exc}'],stdout_tail=read_tail(stdout),stderr_tail=read_tail(stderr),phase=getattr(self,'phase','unknown'),started_at=started_iso,ended_at=datetime.now(timezone.utc).isoformat())
    def enrich_result(self,result,artifact): pass

async def terminate_process_group(proc):
    if proc.returncode is not None: return
    try: os.killpg(proc.pid,signal.SIGTERM)
    except ProcessLookupError: return
    try: await asyncio.wait_for(proc.wait(),timeout=5); return
    except asyncio.TimeoutError: pass
    try: os.killpg(proc.pid,signal.SIGKILL)
    except ProcessLookupError: pass
    try: await proc.wait()
    except Exception: pass

def shlex_quote(value:str)->str:
    import shlex
    return shlex.quote(value)
