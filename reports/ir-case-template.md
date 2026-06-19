# Incident Report: {INCIDENT_NAME}

**Case ID:** {CASE-###}
**Analyst:** Garfield McLeod
**Status:** {Open | Contained | Eradicated | Closed}
**Severity:** {Critical | High | Medium | Low}
**Report date:** {YYYY-MM-DD}
**Classification / TLP:** {AMBER}

---

## 1. Executive Summary
{Non-technical: what happened, business impact, current status, headline recommendation. 4-6 sentences.}

## 2. Incident Overview
| Field | Value |
|-------|-------|
| Detection source | {EDR / SIEM alert / user report} |
| Detected (UTC) | {timestamp} |
| Incident type | {ransomware / exfil / malware / ...} |
| Affected systems | {hosts, count} |
| Affected accounts | {users/service accounts} |
| Initial access vector | {phishing / RDP / vuln} |
| Dwell time | {first activity → detection} |

## 3. Timeline of Events
*(from `scripts/timeline-builder.py` — see `timeline-template.md`)*

| Time (UTC) | Source | Event | Detail |
|------------|--------|-------|--------|
| | | | |

## 4. Technical Analysis
- **Initial access:** {how they got in}
- **Execution / persistence:** {what ran, how they stayed}
- **Privilege escalation / lateral movement:** {accounts, hosts}
- **Actions on objectives:** {encryption / exfil / etc.}

## 5. MITRE ATT&CK Mapping
| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----------|
| | | | |

## 6. Indicators of Compromise
| Type | Indicator | Context |
|------|-----------|---------|
| | | |

## 7. Containment, Eradication & Recovery
{Actions taken, when, by whom, and verification.}

## 8. Impact Assessment
{Data/systems affected, downtime, regulatory/notification considerations.}

## 9. Root Cause
{The underlying gap that allowed the incident.}

## 10. Recommendations & Lessons Learned
- **Detection:** {new rules}
- **Prevention:** {hardening, patching, config}
- **Process:** {playbook/process updates}

## Appendix
Evidence inventory, collection logs, hashes, chain-of-custody references.
