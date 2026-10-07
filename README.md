# ReconForge 4.1 — Advanced Recon CLI

ReconForge is a modular, CLI-first reconnaissance and authorized security-assessment orchestrator. The key design is **evidence-driven sequencing**: scanners are workers, the evidence layer builds a shared attack-surface model, the adaptive engine chooses follow-up work, validators try to reproduce deterministic issues, and a quality gate decides what is reportable.

## Architecture

```text
reconforge/
├── cli.py
├── config.py
├── models.py
├── utils.py
│
├── engine/
│   ├── orchestrator.py
│   ├── scheduler.py
│   ├── state.py
│   └── lifecycle.py
│
├── scanners/
│   ├── base.py
│   ├── nmap.py
│   ├── nikto.py
│   ├── wapiti.py
│   ├── nuclei.py
│   ├── ffuf.py
│   ├── sqlmap.py
│   └── http_probe.py
│
├── evidence/
│   ├── engine.py
│   ├── graph.py
│   ├── normalize.py
│   └── correlate.py
│
├── adaptive/
│   ├── rules.py
│   └── decision_engine.py
│
├── validation/
│   ├── headers.py
│   ├── tls.py
│   ├── cookies.py
│   └── findings.py
│
├── reporting/
│   ├── builder.py
│   └── html.py
│
└── ai/
    └── qwen.py
```

## Runtime pipeline

```text
PRECHECK
  ↓
1. RECON DISCOVERY
  └── Nmap
  ↓
2. WEB VALIDATION
  └── Nikto → Wapiti → Nuclei → ffuf/Feroxbuster
  ↓
EVIDENCE ENGINE
  └── attack surface + endpoint inventory + normalized candidates
  ↓
3. ADAPTIVE FOLLOW-UP
  ├── technology-focused Nuclei
  ├── API-path content discovery
  └── parameterized-endpoint eligibility for SQLMap
  ↓
4. SAFE VALIDATION + PoC GATE
  ├── headers
  ├── cookies
  ├── TLS
  └── bounded SQLMap
  ↓
5. QUALITY GATE + CORRELATION
  ├── confirmed/corroborated → reportable
  └── scanner-only/unverified → Why ReconForge Did NOT Report This
  ↓
6. REPORTING
  ├── report.json
  ├── report.html
  └── optional Qwen GGUF summary
```

## Why it is different from a simple scanner wrapper

ReconForge does not treat tool output as the final answer. Each adapter returns a common `ToolResult`; `EvidenceEngine` merges those results into an evidence graph; `AdaptiveDecisionEngine` converts evidence into bounded next actions; validation adds a second proof layer; and the reporting gate keeps unverified candidates out of the main finding list.

## CLI usage

The safest first run is a dry-run. It shows the real command line without starting scanner processes or passive network probes:

```bash
python3 reconforge.py 127.0.0.1 \
  --authorized \
  --mode advanced \
  --dry-run
```

You will see lines such as:

```text
=== STAGE 1/6 • RECON DISCOVERY ===
COMMAND > nmap -Pn -T4 -sV -O -p- -oX ... 127.0.0.1

=== STAGE 2/6 • WEB VALIDATION ===
COMMAND > nikto -host http://127.0.0.1 ...
COMMAND > wapiti -u http://127.0.0.1 ...
COMMAND > nuclei -u http://127.0.0.1 ...
COMMAND > ffuf -w ... -u http://127.0.0.1/FUZZ ...
```

Each real command is copied into that run's `commands/` directory.

## Kali install

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

sudo apt update
sudo apt install nmap nikto wapiti sqlmap ffuf feroxbuster seclists
```

Verify:

```bash
command -v nmap nikto wapiti sqlmap ffuf feroxbuster nuclei
```

## Advanced assessment

```bash
python3 reconforge.py 127.0.0.1 \
  --authorized \
  --scope scope.example.txt \
  --mode advanced \
  --fuzzer feroxbuster \
  --sqlmap auto \
  --report yes
```

For a parameterized endpoint that has already been discovered, bounded SQLMap can be explicitly forced:

```bash
python3 reconforge.py 'https://app.example.test/item?id=1' \
  --authorized \
  --mode advanced \
  --sqlmap force
```

The SQLMap adapter caps the profile at low risk and does not expose dump, shell, or file-read/write post-exploitation flags.

## Nmap controls

```text
--nmap-scan-type {S,T,U,A,W,M}
--nmap-service
--nmap-os
--nmap-aggressive
--nmap-no-ping
--nmap-ports 80,443,8000-8100
--nmap-web-ports
--nmap-script http-title,http-headers
--nmap-script-args '...'
--nmap-arg=--reason
```

ReconForge reserves machine-readable output flags so the framework-owned XML artifact is not replaced by an operator argument.

## Qwen 4B GGUF

The Qwen component is optional and local. It is a **presentation/triage layer only**; the deterministic engine remains authoritative.

```bash
python3 reconforge.py 127.0.0.1 \
  --authorized \
  --mode advanced \
  --qwen-gguf ~/models/qwen4b.gguf
```

A ZIP containing the GGUF is accepted too:

```bash
python3 reconforge.py 127.0.0.1 \
  --authorized \
  --mode advanced \
  --qwen-gguf ~/models/qwen4b-gguf.zip
```

By default the module looks for `llama-cli`; override it with:

```text
--qwen-bin /path/to/llama-cli
```

The exact local model command is printed as:

```text
COMMAND > llama-cli -m /path/qwen4b.gguf ...
```

## Output

```text
reconforge-results/
└── <host>-<mode>-<scan-id>/
    ├── artifacts/
    ├── logs/
    ├── commands/
    ├── evidence/
    ├── state.json
    ├── report.json
    ├── report.html
    └── qwen-summary.txt
```

The persistent `.history/latest/` snapshot stores enough normalized state to show attack-surface changes between repeated runs.

## Validation and false-positive control

Deterministic checks such as clickjacking, CSP, CORS, cookie flags, directory listing, verbose-error markers, and TLS observations are rechecked with lightweight requests/handshakes. Non-deterministic classes are not presented as confirmed from one scanner hit; they need independent corroboration before entering the main report.

The final HTML report includes:

```text
Why ReconForge Did NOT Report This
```

with the candidate, severity, validation state, and suppression reason.

## Development checks

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
```

Tests are offline/synthetic and do not attack a network target.

## Safety boundary

Use only on assets you are explicitly authorized to assess. The CLI enforces an authorization flag, supports scope files, uses non-shell process execution, limits concurrency, applies process timeouts, and keeps SQLMap in a bounded validation configuration.

## Report templates

ReconForge selects a report template by assessment type. Use `--report-type auto` (default) to infer `web`, `api`, or `network`, or explicitly choose one:

```bash
python3 reconforge.py https://app.example.test --authorized --report-type web
python3 reconforge.py 192.0.2.10 --authorized --report-type network
python3 reconforge.py https://api.example.test/api/v1 --authorized --report-type api
```

The generated HTML report follows the supplied template structure: `EXECUTIVE SUMMARY`, `VULNERABILITY OVERVIEW`, `FINDINGS LOG`, and `Scope & Methodology`, with the findings-table category column adjusted for web/API/network assessments.

## testssl.sh integration

ReconForge integrates the official `testssl.sh` project as a TLS/SSL assessment worker. The upstream project supports TLS/SSL protocol, cipher, certificate, HTTP-header and vulnerability checks and provides machine-readable JSON output. See the upstream documentation for current options. https://github.com/testssl/testssl.sh

Install it from the official GitHub repository:

```bash
./scripts/install_testssl.sh
```

The equivalent upstream clone is:

```bash
git clone --depth 1 https://github.com/testssl/testssl.sh.git tools/testssl.sh
chmod +x tools/testssl.sh/testssl.sh
```

Or point ReconForge to an existing executable:

```bash
python3 reconforge.py https://app.example.test --authorized --testssl-path ~/tools/testssl.sh/testssl.sh
```

For an HTTPS URL ReconForge runs testssl.sh during the web/TLS stage. For a raw IP/host network assessment, it can select an open TLS service discovered by Nmap (for example 443 or 8443). The raw JSON artifact is stored under `artifacts/testssl.json`.


## One-command workflow

Install once on Kali:

```bash
chmod +x scripts/install_reconforge.sh
./scripts/install_reconforge.sh
```

Then simply run:

```bash
reconforge
```

ReconForge prompts for the authorized target once. It infers network/IP versus web versus API-like input, runs the relevant toolchain, and prints every external command as `COMMAND > ...`. Use `--mode basic`, `--mode deep`, or `--mode advanced` to change depth; advanced is the default.


### Fastest operator flow

After installing, the shortest command is:

```bash
reconforge
```

Enter the authorized target when prompted. ReconForge infers `network`, `web`, or `api`, starts with Nmap, then enables web tooling only when HTTP/TLS exposure is actually discovered. `advanced` is the default; `--mode basic` and `--mode deep` remain available.

Nmap NSE coverage is selected from the locally installed Nmap script catalog: `basic` uses `default,discovery,safe`; `deep` adds `vuln`; `advanced` selects all local NSE categories except `brute`, `dos`, `exploit`, and `intrusive`. A filtering/rate-limit signal schedules an adaptive `-T3` retry after the initial `-T4` discovery. Advanced mode also uses Nmap `-A`.

Every external command is printed as `COMMAND > ...` and saved under the run's `commands/` directory.


### One-time Kali toolchain bootstrap

To install the scanner toolchain in one step:

```bash
chmod +x scripts/bootstrap_kali.sh
./scripts/bootstrap_kali.sh
```

This installs the common ReconForge command-line dependencies and pulls the local testssl.sh dependency. After that, the operator command remains simply `reconforge`.
