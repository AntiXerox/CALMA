# CALMA Machine Learning Guide

This document explains how CALMA’s ML pipeline works, how to retrain it, and how to interpret results. It’s professional, but still friendly—no PhD required.

---

## Models Overview

CALMA uses two Logistic Regression models:

- **PE Model** — Windows executables (EXE/DLL)
- **PDF Model** — PDF documents

These models are intentionally lightweight: fast, transparent, and surprisingly effective.

---

## Data Sources

- **PE dataset:** balanced 50/50 clean vs malware
- **PDF dataset:** balanced 50/50 benign vs malicious

Balanced datasets are critical to avoid the “everything is suspicious” bias.

---

## Feature Extraction

### PE Features
- File size
- Section counts
- Section entropy
- Header characteristics
- Suspicious imports

### PDF Features
- Number of pages
- JavaScript presence
- Embedded files
- Automatic actions
- Document structure signals

---

## Thresholds

CALMA uses probability thresholds to classify attachments:

- **Clean:** $p < 0.50$
- **Suspicious:** $0.50 \le p < 0.75$
- **Infected:** $p \ge 0.75$

These thresholds are designed to reduce false positives without missing real threats.

---

## Where Models Live

- Models are stored in [scripts/ml/](scripts/ml/)
- Datasets are also stored in [scripts/ml/](scripts/ml/)

---

## Retraining

To retrain the PE model:

```bash
source venv/bin/activate
python3 scripts/ml/modelo_logistica.py train --balanced
```

The training script will:
- Load the balanced dataset
- Retrain the model
- Write updated `.pkl` files

---

## Evaluation Metrics

Typical metrics you should watch:

- **Accuracy**
- **Precision (clean)**
- **Recall (clean)**
- **F1 Score**
- **ROC-AUC**

If accuracy looks amazing but clean precision collapses, your model is probably biased again. The fix is usually **rebalancing** and **threshold tuning**.

---

## Debugging ML Issues

**Symptoms:**
- Everything is marked suspicious
- Clean files flagged as infected

**Fixes:**
- Rebalance datasets
- Retrain models
- Adjust thresholds in [config/calma_config.json](config/calma_config.json)

---

## Related Docs

- [docs/Security.md](docs/Security.md)
- [README.md](README.md)
- [INSTALL.md](INSTALL.md)
