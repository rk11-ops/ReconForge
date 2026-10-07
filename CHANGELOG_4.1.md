# ReconForge 4.1.1

## One-command operator flow
- `reconforge` or `reconforge <target>` is enough. If `--authorized` is omitted, the CLI asks once whether the target is in-scope.
- Target type is inferred as `web`, `api`, or `network`. After Nmap, HTTP/TLS is still probed so IP targets can enable nikto, testssl.sh, and wapiti when a web surface answers.

## Live NSE catalog
- ReconForge inventories the Nmap `scripts` directory at runtime (Linux and Windows paths).
- `basic` uses installed `default,discovery,safe` categories.
- `deep` adds installed `vuln` scripts.
- `advanced` uses every local NSE category except `brute`, `dos`, `exploit`, and `intrusive`.

## Firewall / IDS adaptation
- Heavy filtering or IDS/firewall wording in Nmap output retries discovery at `-T3` and adds `-A`.
- Timing is slowed; this is not a firewall-bypass or evasion module.

# ReconForge 4.1

## Report templates
- Added `--report-type auto|web|network|api`.
- `auto` classifies explicit HTTP/HTTPS URLs as Web, API-like paths as API, and raw IP/host input as Network.
- HTML reports now follow the supplied template structure: `EXECUTIVE SUMMARY`, `VULNERABILITY OVERVIEW`, `FINDINGS LOG`, and `Scope & Methodology`.
- Findings table columns change by report type (OWASP Category, Affected Host/IP, or OWASP API Category).

## testssl.sh
- Added `TestSSLRunner` backed by the official `testssl/testssl.sh` repository.
- Supports `--testssl-path`, `TESTSSL_PATH`, PATH discovery, and the local `tools/testssl.sh/testssl.sh` checkout.
- Produces `artifacts/testssl.json` using testssl.sh JSON output and normalizes findings into ReconForge evidence.
- HTTPS web targets run testssl.sh automatically. Network assessments can select an open TLS service discovered by Nmap.
- Added `scripts/install_testssl.sh` for a depth-1 clone from the official repository.

## Validation
- `python3 -m compileall -q .` passes.
- `python3 -m unittest discover -s tests -v` passes (12 tests).
