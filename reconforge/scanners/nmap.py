from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from .base import BaseScanner
from ..config import PROFILES, NSE_PROFILES
from ..evidence.normalize import extract_technologies
from ..utils import dedupe_ordered

class NmapScanner(BaseScanner):
    name='nmap'; executable='nmap'
    def __init__(self, ctx, timing_override=None, artifact_suffix='', force_aggressive=False):
        super().__init__(ctx)
        self.timing_override = timing_override
        self.artifact_suffix = artifact_suffix
        self.force_aggressive = force_aggressive
    def build_command(self):
        p=PROFILES[self.ctx.mode]; artifact=self.ctx.output_dir/'artifacts'/f'nmap{self.artifact_suffix}.xml'; args=list(p.nmap_args)
        timing = self.timing_override or getattr(self.ctx, 'nmap_timing', None)
        if timing:
            args=[x for x in args if not (x.startswith('-T') and len(x)==3)] + [f'-T{timing}']
        if self.ctx.nmap_scan_type:
            args=[x for x in args if x not in {'-sS','-sT','-sU','-sA','-sW','-sM'}]; args.append(f'-s{self.ctx.nmap_scan_type}')
        if self.ctx.nmap_service_version and '-sV' not in args: args.append('-sV')
        if self.ctx.nmap_os_detection and '-O' not in args: args.append('-O')
        if (self.ctx.nmap_aggressive or self.force_aggressive) and '-A' not in args: args.append('-A')
        if self.ctx.nmap_no_ping and '-Pn' not in args: args.append('-Pn')
        if self.ctx.nmap_ports:
            cleaned=[]; skip=False
            for t in args:
                if skip: skip=False; continue
                if t=='--top-ports': skip=True; continue
                if t=='-p' or t=='-p-' or t.startswith('-p='): continue
                cleaned.append(t)
            args=cleaned+['-p',self.ctx.nmap_ports]
        scripts=self.ctx.nmap_scripts or (NSE_PROFILES[self.ctx.mode],)
        if scripts: args += ['--script',','.join(scripts)]
        if self.ctx.nmap_script_args: args += ['--script-args',self.ctx.nmap_script_args]
        args += list(self.ctx.nmap_extra_args)
        return ['nmap',*dedupe_ordered(args),'-oX',str(artifact),self.ctx.host],artifact
    def enrich_result(self,result,artifact):
        if not artifact or not artifact.exists(): return
        try:
            import xml.etree.ElementTree as ET
            root=ET.parse(artifact).getroot(); ports=[]; technologies=[]; scripts=[]; open_count=filtered_count=closed_count=0
            for port in root.findall('.//port'):
                state=port.find('state'); svc=port.find('service')
                rec={'port':port.attrib.get('portid'),'protocol':port.attrib.get('protocol'),'state':state.attrib.get('state') if state is not None else None,'service':svc.attrib.get('name') if svc is not None else None,'product':svc.attrib.get('product') if svc is not None else None,'version':svc.attrib.get('version') if svc is not None else None}
                ports.append(rec); technologies += extract_technologies(' '.join(str(rec.get(k) or '') for k in ('service','product','version')))
                if rec['state']=='open': open_count += 1
                elif rec['state']=='filtered': filtered_count += 1
                elif rec['state']=='closed': closed_count += 1
                for script in port.findall('script'):
                    scripts.append({'port':rec['port'],'id':script.attrib.get('id'),'output':script.attrib.get('output')})
            total_scanned=open_count+filtered_count+closed_count
            result.summary={'ports':ports[:1000],'technologies':sorted(set(technologies)),'scripts':scripts[:1000],'open_port_count':open_count,'filtered_port_count':filtered_count,'closed_port_count':closed_count,'filtered_ratio':(filtered_count/total_scanned if total_scanned else 0.0)}
        except Exception as exc: result.notes.append(f'Could not parse Nmap XML: {exc}')
