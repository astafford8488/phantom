<div align="center">

# 👻 PHANTOM

### AI-Powered Detection Engineering & Autonomous Threat Hunting Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Sigma Rules](https://img.shields.io/badge/Sigma-Compatible-orange.svg)](https://github.com/SigmaHQ/sigma)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org/)
[![CI](https://github.com/astafford8488/phantom/actions/workflows/ci.yml/badge.svg)](https://github.com/astafford8488/phantom/actions)

*A production-grade platform that combines Sigma rule execution, ML anomaly detection, autonomous LLM-powered threat hunting, and graph-based alert correlation into a unified detection pipeline — with full MITRE ATT&CK coverage analysis.*

[Features](#features) · [Architecture](#architecture) · [Quick Start](#quick-start) · [Detection Pipeline](#detection-pipeline) · [API Reference](#api-reference)

</div>

---

## The Problem

Security teams face an impossible scaling challenge:

| Challenge | Reality |
|-----------|---------|
| **Alert fatigue** | SOCs receive 10,000+ alerts/day, 80% are false positives |
| **Detection gaps** | Most orgs cover < 20% of MITRE ATT&CK techniques |
| **Manual hunting** | Threat hunting requires expertise that doesn't scale |
| **Siloed tools** | Sigma rules, anomaly detection, and correlation live in separate systems |
| **Slow rule authoring** | Writing validated Sigma rules takes hours per detection |

**PHANTOM solves this** by unifying rule-based detection, ML anomaly analysis, and autonomous AI-powered hunting into a single pipeline — with intelligent alert correlation that turns thousands of alerts into actionable incidents.

## How PHANTOM Compares

| Capability | Traditional SIEM | PHANTOM |
|:-----------|:----------------:|:-------:|
| Sigma Rule Execution | Partial | Full engine with modifiers |
| ML Anomaly Detection | Basic threshold | Isolation Forest + UEBA |
| Autonomous Hunting | Manual only | LLM-powered hypotheses |
| Alert Correlation | Time-window only | Graph-based + kill-chain |
| MITRE Coverage Analysis | Dashboard only | Gap analysis + recommendations |
| Rule Generation | Manual YAML | Natural language → Sigma |
| Detection Pipeline | Minutes | Seconds |

## Features

### Sigma Detection Engine
- Full Sigma specification support (field modifiers, wildcards, logical operators)
- `contains`, `startswith`, `endswith`, `re` field modifiers
- `and`, `or`, `not` logical conditions with `N of X*` aggregation
- Logsource filtering and multi-pattern matching
- Rule validation and LLM-powered rule generation

### ML Anomaly Detection
- **Isolation Forest** — Multivariate outlier detection on event features
- **Statistical Baselines** — Z-score anomaly detection per feature
- **UEBA Profiling** — Per-entity behavioral baselines (hourly activity, known processes, login sources)
- Weighted ensemble scoring with configurable thresholds

### Autonomous Threat Hunting
- **6 Built-in Playbooks** — Lateral movement, persistence, credential access, exfiltration, defense evasion, discovery
- **Pattern Hunting** — Encoded PowerShell, suspicious parent-child processes, brute force detection
- **Temporal Analysis** — Activity burst detection and off-hours anomalies
- **LLM Hypotheses** — Claude-powered hypothesis generation and automated investigation

### Graph-Based Alert Correlation
- Entity overlap detection (shared users, hosts, IPs, processes)
- MITRE ATT&CK kill-chain sequence recognition
- Temporal proximity correlation with configurable windows
- Severity escalation pattern detection
- Connected-component incident grouping

### MITRE ATT&CK Coverage
- 70+ technique catalog across all 14 tactics
- Per-tactic and per-priority coverage breakdown
- Gap analysis with prioritized recommendations
- Heatmap data generation for visualization

## Architecture

```
                          PHANTOM Detection Pipeline
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   ┌──────────┐    ┌───────────┐    ┌──────────────────────────┐    │
│   │  Events  │───▶│ Normalize │───▶│     Detection Engines    │    │
│   │  (JSON,  │    │ (Pipeline)│    │                          │    │
│   │  CEF,    │    └───────────┘    │  ┌────────────────────┐  │    │
│   │  Syslog) │                     │  │   Sigma Engine     │  │    │
│   └──────────┘                     │  │ (Rule Evaluation)  │  │    │
│                                    │  └────────────────────┘  │    │
│                                    │  ┌────────────────────┐  │    │
│                                    │  │ Anomaly Detector   │  │    │
│                                    │  │ (IF + UEBA + Stat) │  │    │
│                                    │  └────────────────────┘  │    │
│                                    └──────────┬───────────────┘    │
│                                               │                    │
│                                    ┌──────────▼───────────────┐    │
│                                    │   Threat Hunter (LLM)    │    │
│                                    │ (Playbooks + Hypotheses) │    │
│                                    └──────────┬───────────────┘    │
│                                               │                    │
│   ┌──────────────┐    ┌───────────────────────▼──────────────┐    │
│   │    MITRE     │◀───│     Alert Correlator (Graph)         │    │
│   │   Coverage   │    │  (Entity + Temporal + Kill-Chain)    │    │
│   │   Analysis   │    └──────────────────────────────────────┘    │
│   └──────────────┘                     │                          │
│                                        ▼                          │
│                              ┌──────────────────┐                 │
│                              │    Incidents      │                 │
│                              │  (Grouped Alerts) │                 │
│                              └──────────────────┘                 │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
git clone https://github.com/astafford8488/phantom.git
cd phantom
pip install -e ".[dev]"
```

### Run Detection Pipeline

```python
import asyncio
from phantom import PhantomEngine

async def main():
    engine = PhantomEngine()

    # Load Sigma rules
    engine.load_rules("rules/")

    # Security events (from SIEM, EDR, or log files)
    events = [
        {
            "CommandLine": "powershell -enc ZQBjAGgAbwA=",
            "process_name": "powershell.exe",
            "username": "jsmith",
            "hostname": "WS-001",
            "category": "process_creation",
            "product": "windows",
        },
        {
            "CommandLine": "mimikatz sekurlsa::logonpasswords",
            "process_name": "mimikatz.exe",
            "username": "admin",
            "hostname": "DC-01",
            "category": "process_creation",
            "product": "windows",
        },
    ]

    # Run full pipeline
    report = await engine.analyze(events, run_hunting=True)

    print(f"Detections: {report.total_detections}")
    print(f"Incidents:  {len(report.incidents)}")
    print(f"Coverage:   {report.coverage.get('percentage', 0):.1f}%")
    print(report.summary())

asyncio.run(main())
```

### CLI Usage

```bash
# Analyze a log file
phantom analyze events.json --rules rules/ --hunt

# Validate a Sigma rule
phantom rules validate rules/suspicious_powershell.yml

# Generate a Sigma rule from description
phantom rules generate "Detect certutil downloading files from external URLs"

# View MITRE ATT&CK coverage
phantom coverage --rules rules/

# Start REST API server
phantom serve --port 8000 --rules rules/
```

## Detection Pipeline

### Stage 1: Log Normalization
```python
from phantom.ingestion.pipeline import LogPipeline

pipeline = LogPipeline()
events = pipeline.normalize([
    {"EventID": "4688", "Computer": "DC-01", "CommandLine": "whoami /all"},
    {"raw": "CEF:0|Vendor|Product|1.0|100|Alert|5|src=10.0.0.1"},
])
# → Normalized to Common Event Schema with enrichment
```

### Stage 2: Sigma Rule Detection
```python
from phantom.detection.sigma_engine import SigmaEngine

sigma = SigmaEngine()
sigma.add_rule_yaml("""
title: Encoded PowerShell
id: ps-001
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
level: high
tags:
    - attack.t1059.001
""")

results = sigma.evaluate(events)
```

### Stage 3: Anomaly Detection
```python
from phantom.detection.anomaly import AnomalyDetector

detector = AnomalyDetector(contamination=0.05)
anomalies = detector.detect(events)
# → Isolation Forest + Statistical + UEBA ensemble
```

### Stage 4: Threat Hunting
```python
from phantom.hunting.hunter import ThreatHunter

hunter = ThreatHunter()
findings = await hunter.hunt(events)
# → Playbook matches + pattern hunts + temporal analysis
```

### Stage 5: Alert Correlation
```python
from phantom.correlation.graph import AlertCorrelator

correlator = AlertCorrelator()
incidents = correlator.correlate(all_alerts)
# → Graph-based grouping with kill-chain recognition
```

## API Reference

### REST Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/analyze` | Run full detection pipeline |
| `POST` | `/v1/sigma/evaluate` | Evaluate Sigma rules against events |
| `POST` | `/v1/sigma/validate` | Validate Sigma rule YAML |
| `POST` | `/v1/sigma/generate` | Generate rule from natural language |
| `POST` | `/v1/anomaly/detect` | Run anomaly detection |
| `GET` | `/v1/rules` | List loaded Sigma rules |
| `GET` | `/v1/coverage` | MITRE ATT&CK coverage report |
| `GET` | `/health` | Health check |

```bash
# Analyze events
curl -X POST http://localhost:8000/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"events": [...], "run_hunting": true}'

# Generate a Sigma rule
curl -X POST http://localhost:8000/v1/sigma/generate \
  -H "Content-Type: application/json" \
  -d '{"description": "Detect ransomware file encryption patterns"}'
```

## Project Structure

```
phantom/
├── src/phantom/
│   ├── __init__.py              # Package exports
│   ├── engine.py                # PhantomEngine orchestrator
│   ├── cli.py                   # Click CLI interface
│   ├── detection/
│   │   ├── sigma_engine.py      # Sigma rule parser & evaluator
│   │   └── anomaly.py           # ML anomaly detection (IF + UEBA)
│   ├── hunting/
│   │   └── hunter.py            # Autonomous threat hunter
│   ├── correlation/
│   │   └── graph.py             # Graph-based alert correlator
│   ├── mitre/
│   │   └── mapper.py            # MITRE ATT&CK coverage engine
│   ├── ingestion/
│   │   └── pipeline.py          # Log normalization pipeline
│   ├── api/
│   │   └── server.py            # FastAPI REST server
│   └── utils/
│       └── logging.py           # Structured logging
├── tests/                       # 80+ unit tests
│   ├── test_sigma.py
│   ├── test_anomaly.py
│   ├── test_correlation.py
│   ├── test_mitre.py
│   ├── test_hunting.py
│   └── test_pipeline.py
├── examples/                    # Usage examples
│   ├── detection_pipeline.py
│   ├── sigma_rules.py
│   └── threat_hunting.py
├── rules/                       # Sample Sigma rules
│   ├── suspicious_powershell.yml
│   ├── credential_dumping.yml
│   └── lateral_movement.yml
├── configs/                     # Configuration profiles
│   ├── default.yaml
│   └── strict.yaml
└── pyproject.toml
```

## Roadmap

- [x] Sigma rule engine with full modifier support
- [x] Isolation Forest + UEBA anomaly detection
- [x] 6 built-in hunting playbooks
- [x] Graph-based alert correlation with kill-chain recognition
- [x] MITRE ATT&CK coverage analysis with gap recommendations
- [x] LLM-powered Sigma rule generation
- [x] REST API and CLI
- [ ] Real-time event streaming (Kafka/Redis)
- [ ] Elasticsearch/Splunk backend integration
- [ ] YARA rule support for file-based detection
- [ ] Transformer-based anomaly detection
- [ ] Interactive MITRE ATT&CK heatmap dashboard
- [ ] Automated rule tuning from false positive feedback
- [ ] Multi-tenant deployment with RBAC

## License

MIT License — see [LICENSE](LICENSE) for details.
</div>
