#  FirewallLogic
## Automated Firewall Policy Auditing & Formal Verification Engine

<p align="center">

A hybrid symbolic reasoning framework for detecting firewall rule anomalies using Logic Programming and Computational Geometry optimization.

</p>


---

## 📌 Overview

Modern enterprise networks rely heavily on Next Generation Firewalls (NGFWs) to enforce security policies.

However, as firewall configurations grow, manual rule management becomes increasingly difficult and error-prone.

Large-scale firewall policies often contain hidden logical inconsistencies such as:

- Shadowed rules
- Redundant policies
- Conflicting permissions
- Unreachable rules
- Overlapping access conditions


FirewallLogic is an automated static analysis framework designed to formally verify firewall policies without interacting with live network traffic.

The system transforms firewall configurations into logical facts and applies symbolic reasoning techniques to prove policy correctness.


---

# 🎯 Research Motivation

Firewall rule evaluation follows a:


Top-Down
First-Match
Priority-Based


execution model.

A single incorrect rule ordering can unintentionally:

- Disable security policies
- Create unauthorized access paths
- Increase firewall processing overhead


FirewallLogic addresses this problem through:


Firewall Configuration

    |
    v

Python Parser

    |
    v

Logical Representation

    |
    v

SWI-Prolog Inference Engine

    |
    v

Security Analysis Report



---

# 🏗️ System Architecture


             Firewall Configuration
          (JSON / CSV / Vendor Export)

                     |
                     v

          +--------------------+
          | Python Parser      |
          +--------------------+

                     |
                     v

          Firewall Facts
          (Logical Rules)

                     |
                     v

          +--------------------+
          | SWI-Prolog Engine |
          +--------------------+

                     |
                     v

          Anomaly Detection

                     |
                     v

          Intelligent Report


---

# 🧠 Core Technologies


| Component | Technology |
|-|-|
| Policy Parser | Python |
| Reasoning Engine | SWI-Prolog |
| Formal Rule Analysis | Logic Programming |
| Optimization | Sweep-Line Algorithm |
| Data Structures | Interval Tree |
| Reporting | Python |


---

# 🔍 Detected Firewall Anomalies


## 1. Shadowing Detection

A rule becomes unreachable when an earlier rule completely covers its condition.


Example:


Rule 1:
ALLOW 192.168.1.0/24 ANY

Rule 2:
DENY 192.168.1.10/32 SSH


Rule 2 will never execute.


---

## 2. Redundancy Detection

Detects duplicated or unnecessary policies.

Example:


ALLOW 10.0.0.0/8 HTTP

ALLOW 10.0.0.0/8 HTTP



---

## 3. Conflict Detection

Identifies overlapping rules with contradictory actions.


Example:


Rule 10:
ALLOW subnet_A port 443

Rule 11:
DENY subnet_A port 443



---

## 4. Generalization Detection

Finds incorrectly ordered rules where specific policies appear after broader ones.


---

# ⚡ Algorithm Optimization


## Problem

Naive anomaly detection compares every rule against every other rule:



O(N²)



For:


10,000 firewall rules


The system performs:


100,000,000 comparisons



which makes large-scale analysis impractical.


---

# 🚀 Proposed Optimization

FirewallLogic introduces a preprocessing optimization based on:

## Sweep-Line Algorithm


Originally used in Computational Geometry for detecting overlapping intervals.


Instead of comparing every rule:


Rule A <---->

Rule B <---->

Compare everything


we extract only possible overlapping candidates:



IP Range Index

    |
    v

Candidate Rule Pairs

    |
    v

Formal Verification



Complexity:


Before:


O(N²)



After:



O(N log N)



The Prolog engine performs reasoning only on meaningful candidates.


---

# 🧩 Implementation Roadmap


## Phase 1
### IP/Subnet Logic Engine

- IP representation
- Subnet comparison
- Port range reasoning


Output:


subnet_logic.pl



---

## Phase 2
### Firewall Anomaly Engine

Implementation of:


- Shadowing
- Redundancy
- Conflict
- Generalization


Output:


firewall_engine.pl



---

## Phase 3
### Python-Prolog Integration

Features:

- Dynamic fact injection
- Configuration parsing
- Automated analysis pipeline


Technologies:


Python
PySWIP
SWI-Prolog



---

## Phase 4
### Reporting & Remediation


Generate:


- JSON Reports
- HTML Reports
- Suggested Fixes


Example:


Recommendation:

Move Rule 15 before Rule 3

Reason:
Rule 3 shadows Rule 15



---

# 📊 Example Output


```json
{
 "rule":15,
 "type":"Shadowing",
 "severity":"High",
 "cause":
 "Covered by Rule 3",
 "recommendation":
 "Reorder firewall policy"
}
🔬 Research Contribution

This project explores the intersection of:

Cybersecurity
Formal Methods
Logic Programming
Computational Geometry
Automated Reasoning

The main research idea is combining:

Symbolic Reasoning

+

Algorithmic Optimization

+

Security Policy Verification
🛣️ Future Work

Possible extensions:

Support Fortinet FortiGate
Cisco ASA parser
Palo Alto parser
Machine Learning based risk scoring
Natural Language firewall explanation
Neuro-Symbolic policy reasoning
👨‍💻 Author

Moein Hassanpour

Computer Science Student

Research Interests:

Neuro-Symbolic AI
Cybersecurity
Formal Verification
Intelligent Systems
📜 License

MIT License
