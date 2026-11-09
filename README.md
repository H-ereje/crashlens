# CrashLens 🔍⚡

<p align="center">
  <b>AI-Powered Terminal Log & Incident Triage Engine</b><br>
  <i>Reverse-engineered from Sentry's fingerprinting algorithm — Built for local speed, zero bloat, and automated AI code fixes.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/tests-passing-brightgreen.svg" alt="Tests">
  <img src="https://img.shields.io/badge/PRs-welcome-orange.svg" alt="PRs Welcome">
</p>

---

## 💡 Why CrashLens?

When production crashes, developers and DevOps engineers face chaotic, multi-gigabyte `.log` files filled with thousands of duplicate errors. 

* **Sentry** is powerful, but heavy: it requires cloud subscriptions or complex Docker swarms.
* **`lnav`** is classic, but old-school: written in C++, hard to script, and has zero AI diagnostic capabilities.

**CrashLens** bridges the gap. It takes the industry-standard **Fingerprinting Algorithm** popularized by Sentry, strips away timestamps, memory addresses, and UUID noise, and groups 10,000 raw lines into **actionable incident cards** with **automated AI code patches (Git Diffs)** right inside your terminal.

```
+-------------------------------------------------------------------------------+
|  10,000 Raw Log Lines                                                         |
|  (Timeouts, NullPointers, DB connection drops, Redis retries)                |
+-------------------------------------------------------------------------------+
                                    │
                                    ▼
       [ CrashLens Fingerprinter (SHA-256 Signature Normalization) ]
                                    │
                                    ▼
+───────────────────────────────────────────────────────────────────────────────+
| [OK] Clustered 10,000 logs into 3 unique incidents (99.9% Noise Reduction!)   |
|                                                                               |
|  #44B21C29F2 [CRITICAL] (x48)  OperationalError: connection to DB refused     |
|  #CF29A45450 [ERROR]    (x12)  AttributeError: 'NoneType' object has no email |
|  #3813B7DEFD [WARN]     (x85)  KeyError: 'auth_token' missing in header       |
+───────────────────────────────────────────────────────────────────────────────+
                                    │
                                    ▼
                 [ AI Engine (Gemini / OpenAI / Offline) ]
                                    │
                                    ▼
                   Actionable Root Cause + Git Diff Patch
```

---

## ⚡ Features

* 🎯 **Sentry-Style Fingerprinting:** Normalizes volatile data (IPs, ISO timestamps, memory pointers `0x7fff...`, UUIDs) to cluster identical bugs.
* 🧠 **Dual AI Diagnostic Engine:**
  * **Online Mode:** Powered by Google Gemini or OpenAI to explain root-cause and generate ready-to-merge `git diff` code patches.
  * **Zero-Dependency Offline Mode:** Built-in heuristic expert system that diagnoses database pools, null pointers, network deadlocks, and missing keys without requiring any internet connection or API keys.
* 🖥️ **Terminal UI with Rich:** Colored tables, severity badges, and structured panels.
* 🌐 **Interactive Dark-Mode HTML Reports:** Single-file HTML report with Tailwind styling that you can share with your team or management.
* 🚀 **Multi-Format Support:** Handles multi-line Python tracebacks, Java stack traces, Node.js errors, JSON logs, and standard syslog formats.

---

## 📊 Comparison

| Feature | Sentry | `lnav` | CrashLens |
| :--- | :---: | :---: | :---: |
| **Local CLI-first** | ❌ (Cloud/Docker) | ✅ | ✅ |
| **Noise-reduction Fingerprinting** | ✅ | ❌ | ✅ |
| **Automated AI Root-Cause Analysis** | ⚠️ (Paid add-on) | ❌ | ✅ (Built-in) |
| **Git Diff Patch Suggestions** | ❌ | ❌ | ✅ |
| **Offline Heuristic Engine** | ❌ | ❌ | ✅ |
| **Zero Heavy Dependencies** | ❌ | ✅ | ✅ (Pure Python + Rich) |

---

## 🛠️ Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/H-ereje/crashlens.git
cd crashlens

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Instant Demo (30 seconds)

Run the built-in demo to see CrashLens analyze a simulated microservice database outage:

```bash
python -m crashlens demo
```

---

## 💻 CLI Usage

### Scan and Cluster Logs
Scan any log file to see the clustered incidents and noise reduction metrics:

```bash
python -m crashlens scan /path/to/production.log
```

### Diagnose an Incident (with Code Patch)
Select an incident fingerprint from the scan table to get an instant diagnosis and suggested code fix:

```bash
# Uses the built-in offline expert system (no API key needed!)
python -m crashlens diagnose /path/to/production.log 44B21C29F2

# Or pass a Gemini / OpenAI API key for deep LLM analysis:
export GEMINI_API_KEY="your-api-key"
python -m crashlens diagnose /path/to/production.log 44B21C29F2
```

### Generate Standalone HTML Report
Export an interactive, dark-mode executive report:

```bash
python -m crashlens report /path/to/production.log --output report.html
```

---

## 🧪 Running Tests

CrashLens includes a comprehensive `pytest` test suite covering fingerprint normalization and multi-line parsing:

```bash
pytest
```

---

## 👤 Author

**Harold Duban Cartagena Moreno**
* **GitHub:** [@H-ereje](https://github.com/H-ereje)
* **LinkedIn:** [harold-cartagena](https://www.linkedin.com/in/harold-cartagena-6b24b0128/)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
