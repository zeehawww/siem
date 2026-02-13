# Mini SIEM Project — Report & Observation Notes

---

## ABSTRACT

This project implements a mini Security Information and Event Management (SIEM) system that ingests SSH authentication logs, normalizes them into structured events, applies rule-based and behavior-analytics detection, and presents findings through a web dashboard. The system addresses common SIEM challenges: **noise reduction** (alert deduplication and severity filtering), **behavior analytics** (user baseline and new-IP detection), and **compliance reporting** (audit-ready summaries). Built with Python and Flask, it demonstrates an end-to-end security monitoring pipeline suitable for educational and portfolio use.

**Keywords:** SIEM, log analysis, security monitoring, behavior analytics, compliance, alert management

---

## 1. INTRODUCTION (Page 1)

Security Information and Event Management (SIEM) systems are central to modern security operations. They collect, normalize, and analyze log data from multiple sources to detect threats and support compliance. This project implements a **mini SIEM** that focuses on SSH authentication logs to illustrate core SIEM concepts: collection, parsing, detection, alerting, and visualization.

### 1.1 Objectives

- Ingest raw SSH auth logs and normalize them into structured JSON events  
- Apply rule-based detection (brute force, compromised account, privilege escalation, root login)  
- Implement behavior analytics (user baseline, new-IP-for-user detection)  
- Reduce alert noise through deduplication and severity filtering  
- Provide a compliance report for audit documentation  

### 1.2 Architecture

The pipeline consists of four modules: **Collector** (reads log files), **Parser** (extracts timestamp, user, IP, event type, severity), **Analyzer** (detection engine with rules and behavior baseline), and **Alerts** (persistence and deduplication). A Flask dashboard serves Logs, Analysis, Alerts, Attack Chain (correlation view), and Compliance pages.

---

## 2. IMPLEMENTATION & FEATURES (Page 2)

### 2.1 Detection Rules

| Rule              | Trigger                          | Severity   |
|-------------------|----------------------------------|------------|
| BRUTE_FORCE       | 3+ failed logins from same IP    | HIGH       |
| COMPROMISED_ACCOUNT | Success after failures         | CRITICAL   |
| PRIV_ESC          | Sudo usage                       | HIGH       |
| ROOT_LOGIN        | Direct root login                | CRITICAL   |
| NEW_IP_FOR_USER   | User logs in from new IP         | MEDIUM     |

### 2.2 Noise Reduction

Alerts with the same type and entity (IP or user) are merged and shown with an occurrence count. Optional severity filtering suppresses LOW or MEDIUM alerts to reduce fatigue.

### 2.3 Compliance Report

The Compliance page summarizes authentication failures by IP, sudo usage by user, and critical alerts. A one-click export produces a plain-text report for audit documentation.

---

## OBSERVATION NOTES (Space for your writing)

### Observation 1: Pipeline behavior
*Write your observations about how the collector, parser, and analyzer work together…*




### Observation 2: Alert quality and noise
*Write your observations about deduplication, severity, and alert fatigue…*




### Observation 3: Behavior analytics
*Write your observations about the NEW_IP_FOR_USER rule and user baseline…*




### Observation 4: Compliance and reporting
*Write your observations about the compliance report and its usefulness for audits…*




---

## REFERENCES (with abstracts for your observation notes)

### Reference 1
**Title:** Security Information and Event Management (SIEM)  
**Source:** NIST Special Publication 800-92, Guide to Computer Security Log Management  
**URL:** https://csrc.nist.gov/publications/detail/sp/800-92/final  

**Abstract:** This NIST guide describes the role of log management in security operations, including log collection, storage, and analysis. It outlines best practices for SIEM deployment, log retention, and correlation. The document emphasizes the importance of centralized log management for incident detection and compliance.

**Your observation on this reference:**
*Write how this reference relates to your project (e.g., log collection, normalization, retention)…*




---

### Reference 2
**Title:** User and Entity Behavior Analytics (UEBA)  
**Source:** Gartner, Market Guide for User and Entity Behavior Analytics  

**Abstract:** UEBA uses machine learning and statistical analysis to establish baselines of normal behavior for users and entities. It flags deviations such as logins from new locations, unusual access patterns, or privilege escalation. UEBA complements traditional rule-based SIEM by detecting insider threats and advanced attacks that evade signature-based rules.

**Your observation on this reference:**
*Write how your NEW_IP_FOR_USER rule relates to UEBA concepts…*




---

### Reference 3
**Title:** Reducing Alert Fatigue in Security Operations  
**Source:** SANS Institute, "Tuning Your SIEM: Reducing False Positives and Alert Fatigue"  

**Abstract:** Alert fatigue occurs when analysts are overwhelmed by low-value or duplicate alerts. Effective SIEM tuning involves deduplication, severity prioritization, and correlation to reduce noise. The paper recommends merging similar alerts, suppressing known-good activity, and focusing analyst attention on high-priority findings.

**Your observation on this reference:**
*Write how your deduplication and severity filtering address alert fatigue…*




---

### Reference 4
**Title:** Log Management and Compliance  
**Source:** PCI DSS Requirements for Logging and Monitoring (Requirement 10)  

**Abstract:** Compliance frameworks such as PCI DSS require organizations to track access to cardholder data, monitor authentication events, and retain audit logs. SIEM systems support compliance by providing centralized logging, alerting on policy violations, and generating audit reports for auditors.

**Your observation on this reference:**
*Write how your compliance report supports audit and compliance needs…*




---

### Reference 5
**Title:** SSH Authentication Log Analysis  
**Source:** OpenSSH documentation, syslog and auth log formats  

**Abstract:** SSH servers log authentication events (success, failure, invalid user) to syslog. Common log formats include timestamp, hostname, process, and message. Parsing these logs enables detection of brute-force attacks, unauthorized access, and privilege escalation via sudo.

**Your observation on this reference:**
*Write how your parser handles SSH auth log format and what events you detect…*




---

## ADDITIONAL REFERENCES (for bibliography)

1. NIST. (2006). *Guide to Computer Security Log Management* (SP 800-92).  
2. Gartner. (2023). *Market Guide for User and Entity Behavior Analytics*.  
3. SANS Institute. *Tuning Your SIEM: Reducing False Positives and Alert Fatigue*.  
4. PCI Security Standards Council. *PCI DSS v4.0, Requirement 10: Log and Monitor*.  
5. OpenSSH. *sshd(8) man page — Authentication and logging*.

---

*End of report. Use the observation sections above to document your findings and relate them to the references.*
