# CALMA — Containerized Automated Lazy Mail Anti-nasties

```
██████╗ █████╗ ██╗     ███╗   ███╗ █████╗
██╔════╝██╔══██╗██║     ████╗ ████║██╔══██╗
██║     ███████║██║     ██╔████╔██║███████║
██║     ██╔══██║██║     ██║╚██╔╝██║██╔══██║
╚██████╗██║  ██║███████╗██║ ╚═╝ ██║██║  ██║
 ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝
```

**CALMA** watches your email attachments like a cautious friend who reads the terms and conditions. Annoying? Sometimes. Useful? Always.

- **Cross-platform:** Linux, macOS, Windows (Git Bash/WSL)
- **Machine Learning:** PE and PDF models with strong accuracy
- **Gmail integration:** automatic labeling and safe handling
- **Multi-layer security:** ML + heuristics + file-type checks

---

## Quick Start

### Linux / macOS
```bash
git clone <repo-url> calma
cd calma
./install_universal.sh
```

### Windows 10/11 (Git Bash recommended)
```bash
git clone <repo-url> calma
cd calma
python install_universal.py
bash calma.sh
```

---

## Features

- **Automatic attachment extraction** with metadata preservation
- **Risk scoring** (clean / suspicious / infected)
- **Gmail label routing** with robust error handling
- **Heuristic analysis** (entropy, double extensions, suspicious strings, MIME mismatch)
- **File neutralization** (remove execute permissions, quarantine)
- **Web dashboard** for monitoring and configuration
- **Cron support** for scheduled scans

---

## Installation

### Requirements
- Python 3.8+
- `jq` (JSON parser)
- Git Bash or WSL for Windows

### Universal installers
- **Linux/macOS:** `./install_universal.sh`
- **Windows:** `python install_universal.py`

### Verify installation
```bash
./test_compatibility.sh
```

---

## Configuration

Edit [config/calma_config.json](config/calma_config.json):

```json
{
  "email_user": "your_email@gmail.com",
  "email_pass": "your_app_password"
}
```

Use a Gmail **App Password** (not your main password). If you’ve ever wanted a good excuse to enable 2FA, this is it.

---

## Usage

### CLI
```bash
./calma.sh
```

### Web UI
```bash
python3 scripts/utils/app.py
```
Then open: http://localhost:5000

---

## Machine Learning

CALMA uses two models:
- **PE (Windows executables):** Logistic Regression
- **PDF:** Logistic Regression

Key points:
- Balanced datasets (50/50 clean vs malware)
- Thresholds: **Clean < 50**, **Suspicious 50–74**, **Infected ≥ 75**

Details: [docs/ML_Calma.md](docs/ML_Calma.md)

---

## Security

- No filename-based whitelists (social engineering resistant)
- Text-only formats treated as safe content types
- Attachment neutralization and quarantine
- Strong hashing and metadata capture

Details: [docs/Security.md](docs/Security.md)

---

## Sandbox & Cleanup

Keep CALMA isolated and the workspace clean after tests:

- recommended VM usage and isolation notes
- cleanup of generated logs, caches, and local envs
- safe re-run guidance after email tests

Details: [docs/Sandox.md](docs/Sandox.md)

---

## Project Structure

```
calma/
├── config/                 # Configuration
├── scripts/
│   ├── detection/          # Detection engine
│   ├── ml/                 # ML models and datasets
│   └── utils/              # Utilities and web UI
├── templates/              # Web UI templates
├── dados/                  # Processed data
├── logs/                   # Logs
└── calma.sh                # Main orchestrator
```

---

## Troubleshooting

- **TemplateNotFound: index.html** → Make sure [templates/index.html](templates/index.html) exists and run `python3 scripts/utils/app.py` from repo root.
- **`jq` not found** → install via your package manager
- **Windows issues** → use Git Bash or WSL

---

## License

See the LICENSE file.
