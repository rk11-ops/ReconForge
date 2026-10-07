import asyncio
import argparse
import tempfile
import unittest
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parent
sys.path.insert(0,str(ROOT))

from reconforge.cli import build_parser, make_context
from reconforge.models import ToolResult
from reconforge.scanners.nmap import NmapScanner
from reconforge.scanners.sqlmap import SQLMapRunner, DANGEROUS_FLAGS
from reconforge.scanners.testssl import TestSSLRunner
from reconforge.evidence.engine import EvidenceEngine
from reconforge.evidence.normalize import normalize_finding
from reconforge.adaptive.decision_engine import AdaptiveDecisionEngine
from reconforge.utils import detect_target_kind
from reconforge.nse import NseInventory, script_spec_for_mode, BLOCKED_CATEGORIES
from reconforge.engine.orchestrator import firewall_or_ids_suspected
from reconforge.validation.findings import validate_findings
from reconforge.engine.lifecycle import snapshot_diff

class CoreTests(unittest.TestCase):
    def args(self,out,**kw):
        d=dict(target='192.0.2.10',mode='advanced',authorized=True,scope=None,client='Demo',assessment='Lab',output_dir=str(out),max_parallel=2,tool_timeout=60,wordlist=None,fuzzer='ffuf',web_url=None,no_adaptive=False,no_diff=False,dry_run=True,report='yes',passive_depth=2,nuclei_tag=[],sqlmap='auto',qwen_gguf=None,qwen_bin=None,nmap_scan_type=None,nmap_service=False,nmap_os=False,nmap_aggressive=False,nmap_no_ping=False,nmap_ports=None,nmap_web_ports=False,nmap_script=[],nmap_script_args=None,nmap_arg=[],interactive=False,report_type='auto',testssl_path=None)
        d.update(kw); return argparse.Namespace(**d)
    def test_target_and_context(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t)))
            self.assertEqual(ctx.host,'192.0.2.10'); self.assertTrue(ctx.scope_attested); self.assertEqual(ctx.mode,'advanced')
    def test_nmap_builder(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t)))
            argv,_=NmapScanner(ctx).build_command()
            self.assertIn('-p-',argv); self.assertIn('-A',argv); self.assertIn('--script',argv); self.assertEqual(argv[-1],'192.0.2.10')
            spec=argv[argv.index('--script')+1]
            for blocked in BLOCKED_CATEGORIES:
                self.assertFalse(spec == blocked)
                self.assertFalse(spec.startswith(blocked+','))
    def test_nmap_t3_retry_builder(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t)))
            argv,_=NmapScanner(ctx,timing_override=3,artifact_suffix='-t3-retry',force_aggressive=True).build_command()
            self.assertIn('-T3',argv)
            self.assertNotIn('-T4',argv)
            self.assertIn('-A',argv)
            self.assertIn('--script',argv)

    def test_sqlmap_bounded(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t),sqlmap='force'))
            argv,_=SQLMapRunner(ctx,'http://192.0.2.10/item?id=1').build_command()
            self.assertIn('--batch',argv); self.assertIn('--smart',argv); self.assertIn('--risk',argv)
            self.assertFalse(DANGEROUS_FLAGS & set(argv))
    def test_evidence_correlation(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t)))
            results=[ToolResult(tool='nuclei',status='completed',summary={'ports':[{'port':'443','protocol':'tcp','state':'open','service':'https','product':'nginx','version':'1.2'}],'findings':[{'name':'Missing X-Frame-Options','severity':'low','matched_at':'http://192.0.2.10/login'}]}),ToolResult(tool='nikto',status='completed',summary={'observations':['Missing X-Frame-Options on /login']})]
            a=EvidenceEngine.analyze(ctx,results,{'technologies':['nginx'],'discovered_links':['http://192.0.2.10/login']})
            self.assertEqual(len(a['findings']),1); self.assertEqual(set(a['findings'][0]['sources']),{'nuclei','nikto'})
    def test_adaptive_api_and_sqlmap(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t),sqlmap='auto'))
            analysis={'attack_surface':{'ports':[{'port':'443','service':'https'}],'technologies':['wordpress'],'endpoints':['https://192.0.2.10/api/items?id=1']}}
            actions=AdaptiveDecisionEngine.decide(ctx,analysis,{'nuclei','wapiti','nikto','fuzzer'})
            kinds={a.type for a in actions}; self.assertIn('fuzzer',kinds); self.assertIn('sqlmap',kinds)
    def test_quality_gate_suppresses_single_source(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t)))
            analysis={'findings':[{'fingerprint':'sql-injection|/x','issue_key':'sql-injection','name':'SQL injection','severity':'high','sources':['nuclei'],'endpoints':['http://192.0.2.10/x']}], 'attack_surface':{}}
            vals=validate_findings(ctx,analysis); self.assertEqual(vals[0]['validation_status'],'scanner-reported')
    def test_snapshot_diff(self):
        old={'snapshot':{'ports':['tcp:80:http'],'technologies':['nginx'],'endpoints':['/old'],'findings':[]}}
        new={'ports':['tcp:443:https'],'technologies':['nginx'],'endpoints':['/new'],'findings':[]}
        d=snapshot_diff(old,new); self.assertEqual(d['added']['ports'],['tcp:443:https']); self.assertEqual(d['removed']['endpoints'],['/old'])
    def test_report_type_auto_web_and_network(self):
        with tempfile.TemporaryDirectory() as t:
            web=make_context(self.args(Path(t),target='https://example.test',web_url='https://example.test'))
            net=make_context(self.args(Path(t),target='192.0.2.10',web_url=None))
            from reconforge.reporting.builder import infer_report_type
            self.assertEqual(infer_report_type(web),'web')
            self.assertEqual(infer_report_type(net),'network')

    def test_testssl_command(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t),target='https://example.test',web_url='https://example.test'))
            scanner=TestSSLRunner(ctx)
            # PATH-independent command shape when no executable is installed.
            argv,_=scanner.build_command()
            self.assertEqual(argv[-1],'https://example.test')
            self.assertIn('--jsonfile-pretty',argv)

    def test_target_kind_auto_detection(self):
        self.assertEqual(detect_target_kind('https://example.test/api/v1'), 'api')
        self.assertEqual(detect_target_kind('https://example.test'), 'web')
        self.assertEqual(detect_target_kind('192.0.2.10'), 'network')

    def test_cli_dry_run_and_help(self):
        p=build_parser(); a=p.parse_args(['192.0.2.10','--authorized','--dry-run','--mode','advanced']); self.assertTrue(a.dry_run)

    def test_live_nse_spec_excludes_blocked(self):
        inv=NseInventory(root=Path('/tmp/nmap/scripts'), scripts={
            'http-title': frozenset({'default','discovery','safe'}),
            'http-vuln-cve2017-5638': frozenset({'vuln','intrusive'}),
            'ftp-brute': frozenset({'brute','intrusive'}),
            'http-slowloris': frozenset({'dos'}),
            'smb-vuln-ms08-067': frozenset({'exploit','vuln'}),
            'ssl-cert': frozenset({'default','safe','discovery'}),
        })
        self.assertEqual(script_spec_for_mode('basic', inv), 'default,discovery,safe')
        self.assertEqual(script_spec_for_mode('deep', inv), 'default,discovery,safe,vuln')
        advanced=script_spec_for_mode('advanced', inv)
        self.assertIn('default', advanced)
        self.assertIn('vuln', advanced)
        self.assertNotIn('brute', advanced)
        self.assertNotIn('dos', advanced)
        self.assertNotIn('exploit', advanced)
        self.assertNotIn('intrusive', advanced)

    def test_firewall_hint_detection(self):
        quiet=ToolResult(tool='nmap',status='completed',summary={'filtered_ratio':0.1})
        noisy=ToolResult(tool='nmap',status='completed',summary={'filtered_ratio':0.2},stdout_tail='possible IDS / firewall dropping probes')
        heavy=ToolResult(tool='nmap',status='completed',summary={'filtered_ratio':0.8})
        self.assertFalse(firewall_or_ids_suspected([quiet]))
        self.assertTrue(firewall_or_ids_suspected([noisy]))
        self.assertTrue(firewall_or_ids_suspected([heavy]))

if __name__=='__main__': unittest.main()
