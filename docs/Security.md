# CALMA Security Guide

CALMA is designed to be careful by default—think of it as a security guard who asks for ID even when you’re clearly the CEO. Below is the security posture, best practices, and what CALMA does (and doesn’t) protect you from.

---

## Security Goals

- **Reduce risk** from malicious email attachments.
- **Classify fast** so you can triage efficiently.
- **Fail safe** (when in doubt, mark as suspicious/infected).

---

## What CALMA Protects Against

- Executable attachments with risky traits.
- PDFs with suspicious markers.
- Files with misleading extensions or MIME mismatches.
- Common social engineering tricks (e.g., deceptive filenames).

---

## What CALMA Does NOT Replace

CALMA is not an enterprise-grade endpoint security suite. It helps with **email attachment triage**, not with:

- Advanced persistent threats (APTs)
- Kernel-level malware
- Zero-day exploits with no known indicators
- Nation-state attacks (that’s above our pay grade)

---

## Core Protections

### 1) Multi-layer Analysis
- **ML models** for PE and PDF classification
- **Heuristic checks** for high-risk indicators
- **MIME consistency checks** to detect disguised files

### 2) Safe Handling
- **Quarantine** for infected files
- **Removal of execute permissions** where applicable
- **Metadata logging** (hashes, sizes, timestamps)
notepad config/calma_config.json
### 3) Label Hygiene (Gmail)
- Clean / Suspicious / Infected labels
- Safe routing to avoid accidental clicks

---

## Operational Best Practices

- **Use a dedicated Gmail account** for scanning.
- **Enable 2FA** and use **App Passwords**.
- Run CALMA inside a **VM** or container for isolation.
- Review logs regularly in [logs/](logs/).

---

## Configuration Safety Tips

- Store credentials only in [config/calma_config.json](config/calma_config.json).
- Keep permissions tight:
  - `chmod 600` on config file
  - `chmod 700` on data/log directories
- Do not commit credentials to version control.

---

## Known Limitations (The “No Magic” Section)

- **False positives** are possible (better safe than sorry).
- **False negatives** can happen (malware evolves).
- **Heuristics** are not full malware sandboxing.

If CALMA misses something, that’s not a feature—please report it.

---

## Incident Response Workflow

1. **Infected detected** → File quarantined
2. **Review metadata** → Confirm classification
3. **Archive evidence** → Keep logs and hashes
4. **Notify stakeholders** → If needed

---

## Security Checklist

- [ ] Gmail account uses App Password
- [ ] Config permissions are restricted
- [ ] Logs are rotating and monitored
- [ ] Templates are served locally only
- [ ] VM isolation in place for high-risk environments

---

## Related Docs

- [docs/ML_Calma.md](docs/ML_Calma.md)
- [README.md](README.md)
- [INSTALL.md](INSTALL.md)
