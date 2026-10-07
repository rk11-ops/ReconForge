# ReconForge 2.x → 4.1 module map

The uploaded project started as a monolithic `reconforge.py`. In 4.0 the same core ideas are split by responsibility.

| Old responsibility | New module |
|---|---|
| CLI parsing / main | `reconforge/cli.py` |
| profiles / constants | `reconforge/config.py` |
| runtime dataclasses | `reconforge/models.py` |
| target/scope/files | `reconforge/utils.py`, `engine/lifecycle.py` |
| subprocess execution | `scanners/base.py` |
| Nmap | `scanners/nmap.py` |
| Nikto | `scanners/nikto.py` |
| Wapiti | `scanners/wapiti.py` |
| Nuclei | `scanners/nuclei.py` |
| ffuf/Feroxbuster | `scanners/ffuf.py` |
| SQLMap | `scanners/sqlmap.py` |
| passive HTTP | `scanners/http_probe.py` |
| evidence normalization | `evidence/normalize.py` |
| evidence graph | `evidence/graph.py` |
| correlation/risk | `evidence/correlate.py` |
| combined evidence engine | `evidence/engine.py` |
| adaptive rules | `adaptive/rules.py` |
| adaptive decisions | `adaptive/decision_engine.py` |
| safe finding checks | `validation/*.py` |
| scheduling/concurrency | `engine/scheduler.py` |
| assessment state | `engine/state.py` |
| pipeline control | `engine/orchestrator.py` |
| report model | `reporting/builder.py` |
| HTML/JSON output | `reporting/html.py` |
| local Qwen | `ai/qwen.py` |

## Request path

```text
cli.py
  ↓
make_context()
  ↓
engine/lifecycle.py
  ↓
engine/orchestrator.py
  ↓
engine/scheduler.py
  ↓
scanners/*
  ↓
evidence/*
  ↓
adaptive/*
  ↓
validation/* + SQLMap
  ↓
quality gate
  ↓
reporting/* + optional ai/qwen.py
```

## Operator tracing

Each external command is printed as `COMMAND > ...`, stored in `commands/`, and represented in `state.json`. Use `--dry-run` to inspect the baseline command plan without starting external scanner processes or passive network requests.
