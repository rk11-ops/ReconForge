# ReconForge 4.1 — Fastest Setup

## One-time Kali setup

```bash
chmod +x scripts/install_all_kali.sh
./scripts/install_all_kali.sh
```

## Windows

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_windows.ps1
reconforge
```

## Run

```bash
reconforge
reconforge https://app.example.test
reconforge 192.0.2.10
```

Enter the target if prompted. Confirm it is authorized. Advanced is the default. ReconForge classifies web vs API vs IP, runs Nmap, then nikto / testssl / wapiti when HTTP or TLS is present.

## Inspect without touching a target

```bash
reconforge 192.0.2.10 --authorized --dry-run
```

Every external command is printed as `COMMAND > ...` and saved in the run's `commands/` directory.

## Profiles

```bash
reconforge --mode basic
reconforge --mode deep
reconforge --mode advanced
```

NSE categories are taken from the Nmap scripts directory on this machine. Basic = `default,discovery,safe`. Deep adds `vuln`. Advanced uses all local categories except `brute`, `dos`, `exploit`, and `intrusive`. Filtering/IDS drops timing from `-T4` to `-T3` and adds `-A`.

## Qwen 4B GGUF

```bash
reconforge --qwen-gguf /path/to/qwen4b.gguf
```

The model weights are supplied separately; the module accepts a `.gguf` file or a ZIP containing one and uses local `llama-cli`.
