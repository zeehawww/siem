# Report organization (thesis-style chapters)

This document mirrors the chapter flow of a standard technical project report (similar to CBIR/FSRIR thesis structure), adapted for **Aegis SIEM Mini**. Replace figure numbers with your institute’s numbering. Cross-reference `docs/PROJECT_REPORT.md` and `PROJECT_REPORT.md` for technical detail.

---

## Chapter 1 — Introduction

- **Background:** Role of SIEM in security operations; log-centric threat detection and compliance.  
- **Problem statement:** Alert fatigue, limited explainability, stale alert queues, cost/complexity of commercial SIEMs.  
- **Scope:** macOS-centric auth telemetry, rule + behavior analytics, Flask dashboard; out-of-scope (enterprise scale, all log types).  
- **Objectives:** Ingest → parse → detect (MITRE-mapped) → enrich (ATRS, SRTC, DNA, narratives) → present → compliance export.  
- **Report structure:** Brief pointer to Chapters 2–8.

---

## Chapter 2 — Literature review

Survey **relevant** work and standards (with citations you will add):

- **SIEM and log management:** Centralized collection, normalization, retention (e.g. NIST SP 800-92).  
- **Rule-based and signature detection:** Correlation, thresholding, MITRE ATT&CK as a vocabulary for mapping alerts.  
- **Behavior analytics / UEBA:** Baselines, anomalies, entity-centric scoring (conceptual contrast with your simpler baselines).  
- **Alert fatigue and tuning:** Deduplication, severity, analyst workflow (e.g. industry/SANS-style guidance).  
- **Explainability in security analytics:** Need for human-auditable rationales (links to your per-alert XAI fields).  
- **Compliance and audit logging:** PCI DSS Req. 10–style expectations; audit reports from security telemetry.  
- **Related tools (positioning only):** Commercial SIEMs (Splunk, QRadar, Microsoft Sentinel) as context—not reimplementations of their internals.

*Goal:* Show your design is grounded in known problems and prior art; avoid claiming “no one has ever done X” without sources.

---

## Chapter 3 — Challenges and proposed directions

**3.1 Challenges in mini-SIEM and log-based detection**

- Heterogeneous log formats and noisy parsing.  
- High false-positive rates and duplicate alerts.  
- Linking low-level events to tactics/techniques and analyst-readable stories.  
- Operating on **real** host telemetry vs. synthetic demos.  
- Resource limits (single-machine, educational scope).

**3.2 Your response (problem–solution mapping)**

- **Ingestion breadth:** macOS ASL, wtmp, Unified Log, optional UDP syslog—reducing “toy SIEM” limitation.  
- **Noise reduction:** Alert manager deduplication/suppression; decayed risk over time.  
- **Richer scoring:** ATRS (multi-factor entity score), SRTC (sequence-style coefficient)—position as *your* engineering contribution with clear formulas and limitations.  
- **Analyst experience:** Dashboard pages (SOC, alerts, logs, intelligence, compliance, correlation, live data).  
- **“Dataset” analogue:** Describe **evaluation corpora**: real `real_auth.log`, synthetic scenarios, syslog fixtures—what you used to validate behavior (not CUFS-style images; same *role* as “extended dataset” in your template).

**3.3 Optional subsection — scale and deployment**

- Local vs. future cloud/back-end for large retention (if you discuss it).  
- Performance considerations (batch pipeline vs. live listener).

---

## Chapter 4 — Proposed system (design)

**4.1 High-level architecture (Figure 4.1)**  
Pipeline: Collect → Parse → Detect → Enrich → Narrate/Predict → Present (align with `docs/PROJECT_REPORT.md` six-stage diagram).

**4.2 Data flow diagram (Figure 4.2)**  
Raw logs → structured events JSON → alert objects → storage (`storage/*.json`) → API/dashboard.

**4.3 UML / component view (Figure 4.3)**  
Packages: `collector`, `parser`, `analyzer`, `alerts`, `dashboard`; key classes or modules (keep consistent with repo).

**4.4 Major modules (detail)**

| Module | Responsibility |
|--------|----------------|
| **Log collection & reception** | File collectors, UDP syslog listener |
| **Parsing & normalization** | Unified event schema |
| **Detection & enrichment** | Rules, MITRE mapping, ATRS/SRTC, velocity/entropy/prediction/TBF as applicable |
| **Alert lifecycle** | Persistence, dedup, decay, feedback hooks |
| **Presentation** | Flask routes, templates, exports |

**4.5 Data processing and model/training narrative**  
- For **rule + heuristic** systems: describe “training” as baseline learning / parameter choices, not only neural training.  
- If you include Markov/prediction: state training data (event sequences) and limitations.

**4.6 Feasibility study**

- **Economic:** Open stack, no license cost; hardware assumptions.  
- **Technical:** Python3.9+, Flask, macOS APIs; risks (permissions, log access).  
- **Social/operational:** Usability for analysts/students; ethical use of logs (privacy, consent on shared machines).

---

## Chapter 5 — Implementation and testing

**5.1 Implementation overview**  
Repo layout, `aegis` CLI (`collect`, `analyze`, `serve`, etc.), configuration, storage paths.

**5.2 Illustrative I/O (Figures 5.1, 5.2)**  
Example: input log snippet → dashboard alert card or synthesized narrative; or compliance export screenshot.

**5.3 Testing strategy**

- **Unit testing:** Parser rules, single detection functions, score components (where tests exist or should exist).  
- **Integration testing:** End-to-end `aegis analyze` or `main.run_pipeline()` with fixture logs; dashboard API smoke tests.  
- **Functional / UAT:** Requirements traceability—each objective in Chapter 1 mapped to a test case (e.g. brute-force scenario → HIGH alert).

**5.4 Test artifacts (Figure 5.3 optional)**  
e.g. augmentation or log-fixture matrix (parallel to “image augmentation” figure in your template).

---

## Chapter 6 — Results and discussion

- **Quantitative:** Event counts, alert counts before/after dedup, example ATRS/SRTC rankings, decay behavior over time (tables or graphs).  
- **Qualitative:** Explainability text quality, narrative usefulness, MITRE mapping consistency.  
- **Comparison:** Baseline “rules only” vs. “rules + enrichment”; or your system vs. manual log review (honest limits).  
- **Figures 6.1, 6.2:** e.g. dashboard screenshots, score distributions, or timeline of alerts.

*Discuss failure modes:* parser gaps, platform-specific paths, adversarial log injection caveats.

---

## Chapter 7 — Conclusion and future enhancements

- **Summary:** What was built; which objectives were met.  
- **Contributions:** Clear list (pipeline, algorithms, UX, compliance export).  
- **Future work:** More log sources, stronger UEBA/ML, HA deployment, authentication for dashboard, automated tests expansion, SIEM export formats (CEF/LEEF), optional always-on agent, cloud log sinks.

---

## Chapter 8 — Source code and presentation

- **Repository structure** (tree or table).  
- **Key entry points:** `main.py`, `aegis_cli.py`, `dashboard/app.py`.  
- **Short code snippets** (non-exhaustive): parser regex or one detection rule, one API route.  
- **Poster / demo:** One-slide storyboard: problem → architecture → screenshot → results; viva Q&A notes.

---

## Appendices (optional)

- Full MITRE mapping table.  
- Alert schema JSON example.  
- Extended bibliography.

---

*Institute-specific front matter (certificate, declaration, acknowledgements) usually precedes Chapter 1; follow your department template.*
