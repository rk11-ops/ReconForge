from __future__ import annotations
import asyncio
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

console=Console()

def dashboard(scanners,statuses,phase):
    t=Table(title=f'ReconForge Runtime • {phase}',expand=True); t.add_column('Index'); t.add_column('Tool',style='cyan'); t.add_column('Status'); t.add_column('Backend',style='dim')
    styles={'running':'yellow','completed':'green','skipped':'yellow','failed':'red','timeout':'red','dry-run':'magenta','queued':'dim'}
    for i,s in enumerate(scanners):
        st=statuses.get(f'{i}:{s.name}','queued'); t.add_row(str(i),s.name,Text(st,style=styles.get(st,'white')),str(getattr(s,'backend',s.executable or '-')))
    return t

async def execute_scanners(scanners,max_parallel,phase='unknown',state=None):
    sem=asyncio.Semaphore(max_parallel); statuses={f'{i}:{s.name}':'queued' for i,s in enumerate(scanners)}
    with Live(dashboard(scanners,statuses,phase),console=console,refresh_per_second=8,transient=False) as live:
        async def one(i,s):
            async with sem:
                s.phase=phase
                statuses[f'{i}:{s.name}']='running'; live.update(dashboard(scanners,statuses,phase),refresh=True)
                if state:
                    state.event('tool_start',tool=s.name,phase=phase)
                r=await s.run(); r.phase=phase; statuses[f'{i}:{s.name}']=r.status; live.update(dashboard(scanners,statuses,phase),refresh=True)
                if state:
                    state.tool_results.append(r); state.event('tool_end',tool=r.tool,status=r.status,phase=phase,duration=r.duration_seconds); state.save()
                return r
        results=await asyncio.gather(*(one(i,s) for i,s in enumerate(scanners))) if scanners else []
    return results

async def execute_sequential(scanners,phase,state=None):
    results=[]
    for s in scanners:
        results.extend(await execute_scanners([s],1,phase,state))
    return results
