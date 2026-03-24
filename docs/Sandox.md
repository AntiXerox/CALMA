# Sandox — Safety & Cleanup Guide

CALMA is safest when treated like a lab tool: isolated, reproducible, and easy to reset.

---

## Why a sandbox

- Malware analysis can be risky even with safeguards
- Isolation prevents accidental host compromise
- Snapshots make testing repeatable

Recommended environments:
- VirtualBox
- VMware
- QEMU/KVM
- Hyper-V

---

## Cleanup after tests

Keep the workspace lean by removing generated artifacts:

- Logs under `logs/`
- Python cache under `__pycache__/` and `scripts/**/__pycache__/`
- Local virtual environment under `venv/`

If you need to reset email processing, mark test messages as unread and rerun:

```bash
./calma.sh
```

---

## Safe reruns

- Ensure Gmail App Password is configured
- Run from the repo root
- Review labels in Gmail after each test

---

## Notes

This document reflects the latest workflow updates (UID-based email tracking and cleanup guidance).
