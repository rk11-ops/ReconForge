from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

@dataclass(frozen=True)
class ScanProfile:
    mode: str
    nmap_args: tuple[str, ...]
    stages: tuple[str, ...]
    fuzzer_preference: str = "auto"
    fuzzer_depth: int = 1
    fuzzer_threads: int = 20
    fuzzer_rate: int = 50
    nuclei_rate: int = 50
    nuclei_concurrency: int = 25
    nikto_tuning: Optional[str] = None
    wapiti_level: Optional[int] = None
    nuclei_dast: bool = False
    adaptive_budget: int = 6
    sqlmap_level: int = 1
    sqlmap_risk: int = 1
    sqlmap_crawl: int = 0

@dataclass
class ToolResult:
    tool: str
    status: str
    returncode: Optional[int] = None
    duration_seconds: float = 0.0
    command: list[str] = field(default_factory=list)
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    artifacts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""
    summary: dict[str, Any] = field(default_factory=dict)
    phase: str = "unknown"
    started_at: Optional[str] = None
    ended_at: Optional[str] = None

@dataclass
class RunContext:
    target: str
    host: str
    web_url: str
    mode: str
    output_dir: Path
    history_root: Path
    tool_timeout: int
    max_parallel: int
    target_kind: str
    fuzzer: str
    custom_wordlist: Optional[Path]
    nmap_scan_type: Optional[str]
    nmap_service_version: bool
    nmap_os_detection: bool
    nmap_aggressive: bool
    nmap_no_ping: bool
    nmap_ports: Optional[str]
    nmap_scripts: tuple[str, ...]
    nmap_script_args: Optional[str]
    nmap_extra_args: tuple[str, ...]
    nuclei_tags: tuple[str, ...]
    scope_attested: bool
    scope_file: Optional[Path] = None
    client_name: Optional[str] = None
    assessment_name: Optional[str] = None
    adaptive: bool = True
    diff_enabled: bool = True
    adaptive_budget: int = 8
    sqlmap_mode: str = "off"
    qwen_gguf: Optional[Path] = None
    qwen_bin: Optional[str] = None
    report_enabled: bool = True
    dry_run: bool = False
    passive_depth: int = 1
    report_type: str = "auto"
    testssl_path: Optional[Path] = None
    state_file: Optional[Path] = None

@dataclass
class AdaptiveAction:
    type: str
    reason: str
    priority: int = 50
    base_path: str = "/"
    label: str = "adaptive"
    tags: tuple[str, ...] = ()
    budget_cost: int = 1

@dataclass
class FindingCandidate:
    issue_key: str
    name: str
    severity: str
    source: str
    endpoint: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

@dataclass
class ValidationRecord:
    status: str
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
