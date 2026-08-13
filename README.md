# FirewallLogic  
## Automated Firewall Policy Auditing & Formal Verification Engine  

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/SWI--Prolog-8.0%2B-red?logo=swi-prolog" alt="SWI-Prolog">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

---

## 🚀 Quick Start

```bash
# 1. Install SWI-Prolog (system package, not pip-installable)
#    Ubuntu/Debian: sudo apt install swi-prolog
#    macOS:         brew install swi-prolog
#    Windows:       https://www.swi-prolog.org/download/stable

# 2. Set up Python environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3a. Run the web UI
python3 webapp.py                # then open http://127.0.0.1:5000/

# 3b. ...or use the CLI instead
python3 main.py --demo                       # built-in sample config
python3 main.py demo_university_firewall.rules --format text
python3 main.py your_config.rules --format json
```

---

## 📌 Overview

Modern enterprise networks rely heavily on Next‑Generation Firewalls (NGFWs) to enforce security policies. However, as firewall configurations grow, manual rule management becomes increasingly difficult and error‑prone. Large‑scale policies often hide logical inconsistencies such as:

- **Shadowed rules** – rules that never match  
- **Redundant policies** – duplicate or unnecessary entries  
- **Conflicting permissions** – overlapping rules with contradictory actions  
- **Unreachable rules** – rules positioned after more general ones  
- **Overlapping access conditions** – ambiguous decision paths  

**FirewallLogic** is an automated static analysis framework that formally verifies firewall policies **without** interacting with live network traffic. It transforms configuration files into logical facts and applies symbolic reasoning techniques to prove policy correctness.

---

## 🎯 Research Motivation

Firewall rule evaluation follows a **top‑down, first‑match, priority‑based** execution model. A single incorrect rule ordering can unintentionally:

- Disable security policies  
- Create unauthorised access paths  
- Increase firewall processing overhead  

This project bridges the gap between **cybersecurity**, **formal methods**, and **algorithmic optimisation** to provide a robust verification tool.

---

## 🏗️ System Architecture

```
     Firewall Configuration
  (JSON / CSV / Vendor Export)
              │
              ▼
     ┌─────────────────┐
     │  Python Parser  │
     └─────────────────┘
              │
              ▼
     Firewall Facts
   (Logical Predicates)
              │
              ▼
     ┌─────────────────┐
     │ SWI‑Prolog      │
     │ Inference Engine│
     └─────────────────┘
              │
              ▼
   Anomaly Detection
              │
              ▼
     Intelligent Report
```

---

## 🧠 Core Technologies

| Component            | Technology          |
|----------------------|---------------------|
| Policy Parser        | Python 3.8+         |
| Reasoning Engine     | SWI‑Prolog 8.0+     |
| Formal Rule Analysis | Logic Programming   |
| Optimisation         | Sweep‑Line Algorithm|
| Data Structures      | Interval Trees      |
| Reporting            | Python (JSON/HTML)  |

---

## 🔍 Detected Firewall Anomalies

### 1. Shadowing Detection  
A rule becomes unreachable when an earlier rule completely covers its condition.

**Example:**  
```
Rule 1: ALLOW  192.168.1.0/24   ANY
Rule 2: DENY   192.168.1.10/32  SSH
```
→ Rule 2 will never execute.

---

### 2. Redundancy Detection  
Detects duplicated or unnecessary policies.

**Example:**  
```
ALLOW  10.0.0.0/8   HTTP
ALLOW  10.0.0.0/8   HTTP   ← duplicate
```

---

### 3. Conflict Detection  
Identifies overlapping rules with contradictory actions.

**Example:**  
```
Rule 10: ALLOW   subnet_A   port 443
Rule 11: DENY    subnet_A   port 443
```

---

### 4. Generalisation Detection  
Finds incorrectly ordered rules where specific policies appear after broader ones.

---

## ⚡ Algorithm Optimisation

### The Problem  
Naive anomaly detection compares every rule against every other rule — **O(N²)** complexity. For **10,000** firewall rules, this means **100,000,000** comparisons, making large‑scale analysis impractical.

### Proposed Optimisation  
FirewallLogic introduces a preprocessing step based on the **Sweep‑Line Algorithm**, originally used in computational geometry for detecting overlapping intervals.

Instead of comparing all rules, we extract only **possible overlapping candidates** using IP range indexing:

```
    IP Range Index
         │
         ▼
 Candidate Rule Pairs
         │
         ▼
 Formal Verification
```

**Complexity reduction:**  
- Before: O(N²)  
- After:  **O(N log N)**  

The Prolog engine performs symbolic reasoning only on the candidate pairs that truly matter.

### ⚠️ Known limitation: dual-stack (mixed IPv4/IPv6) configs

The sweep-line pre-filter sorts every rule's destination range onto **one
shared numeric axis**, regardless of address family (an IPv6 /128 range
is a much larger integer than any IPv4 range, but both are just integers
to the sweep). This is **not a correctness bug** — every detector still
calls `same_family/2` before accepting a candidate pair, so an IPv4 rule
can never be reported as shadowing/conflicting-with an IPv6 rule. It only
means the pre-filter's speedup is reduced on heavily dual-stack configs:
some IPv4-vs-IPv6 candidate pairs survive the sweep only to be rejected
one step later inside the detector, instead of being filtered out at
sweep time. The benchmark numbers above (`13.8s → 0.45s`) were measured
on an IPv4-only config; a config that mixes both families heavily would
see a smaller (but still positive) speedup. Splitting the sweep into two
per-family passes would close this gap — not implemented in v1 pending
confirmation this actually matters for a real config (see *Future Work*).

---

## 📊 Example Output

```json
{
  "rule": 15,
  "type": "Shadowing",
  "severity": "High",
  "cause": "Covered by Rule 3",
  "recommendation": "Reorder firewall policy – move Rule 15 before Rule 3"
}
```

---

## 🛠️ Operational Features (beyond the core detector)

These were added on top of the tested Phase 1–4 detection pipeline
without modifying `firewall_engine.pl`, `ip_subnet.pl`, `bridge.py`, or
`parser.py` — they wrap the existing, already-verified engine rather
than changing it.

### Check new rules against an existing config (`/check-new`)
For a config that's already been audited and trusted, upload it
alongside a second file containing *only* the rules you're proposing
to add. The tool re-numbers the new rules to avoid ID collisions, runs
the same detector across the combined rule set, and shows only the
findings that involve at least one new rule — old-vs-old findings you
already reviewed are not re-surfaced. Useful for a quick "will this
change break anything?" check before applying it, without re-reviewing
an entire large ruleset every time.

### Audit log (`audit_log.csv`)
Every completed analysis (full or incremental) appends one row —
timestamp, source filename(s), rule/finding counts by severity, which
engine backend ran it — to `audit_log.csv` next to the app. Plain CSV,
append-only, fail-open (a logging failure never blocks or corrupts an
actual analysis). Not committed to git (see `.gitignore`).

### Optional access control
The web UI is open by default (matching the original zero-setup
`python3 webapp.py` workflow). Setting the `FIREWALLLOGIC_PASSWORD`
environment variable turns on HTTP Basic Auth for every route. This is
a single shared password, not a real multi-user login system — see
*Known Limitations* below for what a production multi-user deployment
would still need.

### 🔜 Planned, not yet built
- **PDF / CSV report export** — download links on each report page.
  Deferred for now; will be added once the on-screen report UI itself
  is finalized.

### ⚠️ Known limitations of the operational layer
- **The audit log is process-local** — it's a plain file
  (`audit_log.csv`) next to `webapp.py`, so it doesn't coordinate
  across multiple separate worker processes (e.g. several `gunicorn`
  workers) without extra work. Fine for the single-process deployment
  this project ships with today.
- **Basic Auth is a single shared password**, not per-user accounts,
  roles, or audit-log attribution of *who* ran an analysis (the log
  records *what* was analyzed and *when*, not *by whom*). Also note
  Basic Auth credentials are base64-encoded, not encrypted — run this
  behind HTTPS/a reverse proxy if it's ever exposed beyond
  localhost/a trusted LAN.

---

## 🔬 Research Contribution

This project explores the intersection of:

- **Cybersecurity**  
- **Formal Methods**  
- **Logic Programming**  
- **Computational Geometry**  
- **Automated Reasoning**  

The core idea is to combine **symbolic reasoning** with **algorithmic optimisation** for scalable security policy verification.

---

## 🚀 Future Work

- Support for **Fortinet FortiGate**, **Cisco ASA**, and **Palo Alto** parsers  
- **Machine Learning** based risk scoring  
- Natural‑language explanation of policy violations  
- **Neuro‑symbolic** policy reasoning  

---

## 👨‍💻 Author

**Moein Hassanpour**  
Computer Science Student  
Research Interests: Neuro‑Symbolic AI, Cybersecurity, Formal Verification, Intelligent Systems

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.
