# FirewallLogic  
## Automated Firewall Policy Auditing & Formal Verification Engine  

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/SWI--Prolog-8.0%2B-red?logo=swi-prolog" alt="SWI-Prolog">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

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
