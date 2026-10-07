from __future__ import annotations
import json
import os
import shutil
from pathlib import Path
from .base import BaseScanner
from ..config import TESTSSL_REPO_URL
from ..evidence.normalize import infer_severity


class TestSSLRunner(BaseScanner):
    """Run the official testssl.sh CLI and normalize its JSON findings."""
    name = "testssl.sh"
    executable = "testssl.sh"

    def __init__(self, ctx, target: str | None = None):
        super().__init__(ctx)
        self.target = target or getattr(ctx, "web_url", "")

    def _discover(self) -> str | None:
        candidates = []
        configured = getattr(self.ctx, "testssl_path", None)
        if configured:
            candidates.append(str(configured))
        env_path = os.environ.get("TESTSSL_PATH")
        if env_path:
            candidates.append(env_path)
        which = shutil.which("testssl.sh")
        if which:
            candidates.append(which)
        candidates.extend([
            str(Path.cwd() / "tools" / "testssl.sh" / "testssl.sh"),
            str(Path.cwd() / "testssl.sh"),
            str(Path.home() / "tools" / "testssl.sh" / "testssl.sh"),
        ])
        for c in candidates:
            p = Path(c).expanduser()
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
        return None

    def available(self):
        return bool(self._discover())

    def build_command(self):
        if not self.target:
            raise ValueError("No TLS target available. Supply an HTTPS URL.")
        exe = self._discover() or self.executable
        artifact = self.ctx.output_dir / "artifacts" / "testssl.json"
        argv = [exe, "--quiet", "--warnings", "batch", "--jsonfile-pretty", str(artifact), self.target]
        return argv, artifact

    def enrich_result(self, result, artifact):
        parsed = {}
        if artifact and artifact.exists():
            try:
                parsed = json.loads(artifact.read_text(encoding="utf-8", errors="replace"))
            except Exception as exc:
                result.notes.append(f"Could not parse testssl.sh JSON: {exc}")
        findings, observations = [], []
        if isinstance(parsed, dict):
            self._walk_json(parsed, findings, observations)
        if not findings:
            for line in (result.stdout_tail or "").splitlines():
                clean = line.strip()
                if not clean or clean.startswith(("#", "Testing", "Start", "Done")):
                    continue
                sev = infer_severity(clean)
                if sev in {"critical", "high", "medium", "low"}:
                    findings.append({"name": clean, "severity": sev, "source": "testssl.sh"})
                elif clean:
                    observations.append(clean)
        result.summary = {
            "findings": findings[:500],
            "observations": observations[:500],
            "target": self.target,
            "repository": TESTSSL_REPO_URL,
            "json_artifact": str(artifact) if artifact else None,
            "finding_count": len(findings),
        }

    def _walk_json(self, obj, findings, observations, section=""):
        if isinstance(obj, dict):
            if "finding" in obj and str(obj.get("finding") or "").strip():
                text = str(obj["finding"]).strip()
                sev = str(obj.get("severity") or infer_severity(text)).lower()
                if sev not in {"critical", "high", "medium", "low", "info"}:
                    sev = infer_severity(text)
                findings.append({
                    "name": text,
                    "severity": sev,
                    "identifier": obj.get("id") or obj.get("identifier"),
                    "section": section,
                })
            for key, value in obj.items():
                if key in {"finding", "severity"}:
                    continue
                self._walk_json(value, findings, observations, key if isinstance(key, str) else section)
        elif isinstance(obj, list):
            for value in obj:
                self._walk_json(value, findings, observations, section)
        elif isinstance(obj, str) and obj.strip() and len(obj.strip()) < 500:
            text = obj.strip()
            if text.lower() not in {"ok", "not offered", "not vulnerable", "unknown"}:
                observations.append(text)
