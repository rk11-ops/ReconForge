from __future__ import annotations
import json, re, shutil
from .base import BaseScanner
from ..config import PROFILES, default_wordlist_candidates
from ..utils import normalize_relative_path, sanitize_filename
from ..evidence.normalize import extract_urls_from_lines

class FuzzerEngine(BaseScanner):
    name='fuzzer'
    def __init__(self,ctx,base_path='/',label=''):
        super().__init__(ctx); self.backend=self.select_backend(); self.executable=self.backend; self.base_path=normalize_relative_path(base_path); self.label=sanitize_filename(label or (self.base_path.strip('/').replace('/','_') or 'root'))
    def select_backend(self):
        requested=self.ctx.fuzzer
        if requested!='auto': return requested
        preferred=PROFILES[self.ctx.mode].fuzzer_preference
        for c in (preferred,'ffuf' if preferred!='ffuf' else 'feroxbuster'):
            if shutil.which(c): return c
        return preferred
    def _wordlist(self):
        if self.ctx.custom_wordlist: return self.ctx.custom_wordlist
        for p in default_wordlist_candidates(self.ctx.mode):
            if p.is_file(): return p
        return None
    def available(self): return bool(shutil.which(self.executable or ''))
    def build_command(self):
        wordlist=self._wordlist()
        if not wordlist:
            if self.ctx.dry_run:
                candidates=default_wordlist_candidates(self.ctx.mode)
                wordlist=candidates[0] if candidates else None
            if not wordlist: raise FileNotFoundError('No suitable wordlist; install SecLists or pass --wordlist')
        p=PROFILES[self.ctx.mode]; suffix='' if self.base_path=='/' else f'_{self.label}'
        root=self.ctx.web_url.rstrip('/')+self.base_path
        if self.backend=='ffuf':
            artifact=self.ctx.output_dir/'artifacts'/f'ffuf{suffix}.json'; url=root.rstrip('/')+'/FUZZ'
            return ['ffuf','-w',str(wordlist),'-u',url,'-mc','all','-of','json','-o',str(artifact),'-t',str(p.fuzzer_threads),'-rate',str(p.fuzzer_rate),'-s'],artifact
        artifact=self.ctx.output_dir/'artifacts'/f'feroxbuster{suffix}.txt'
        return ['feroxbuster','-u',root.rstrip('/')+'/','-w',str(wordlist),'-o',str(artifact),'-q','--depth',str(p.fuzzer_depth),'-t',str(p.fuzzer_threads)],artifact
    def enrich_result(self,result,artifact):
        result.notes.append(f'Fuzzer backend: {self.backend}; base path: {self.base_path}')
        if not artifact or not artifact.exists(): return
        try:
            if self.backend=='ffuf':
                data=json.loads(artifact.read_text(encoding='utf-8',errors='replace')); rs=data.get('results',[]) if isinstance(data,dict) else []
                result.summary={'result_count':len(rs),'endpoints':[str(x.get('url')) for x in rs if isinstance(x,dict) and x.get('url')][:1000],'results':rs[:1000]}
            else:
                lines=[x.strip() for x in artifact.read_text(encoding='utf-8',errors='replace').splitlines() if x.strip()]; result.summary={'line_count':len(lines),'endpoints':extract_urls_from_lines(lines)[:1000],'sample':lines[:500]}
        except Exception as exc: result.notes.append(f'Could not parse fuzzer artifact: {exc}')
