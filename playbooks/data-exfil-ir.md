# Playbook: Data Exfiltration Incident Response

**Scope:** Suspected unauthorized data transfer out of the environment.
**Framework:** NIST SP 800-61r2.
**Severity:** High → Critical depending on data sensitivity.

## 1. Detection indicators
- Large/abnormal outbound transfers (volume, off-hours, to new destinations)
- Data staging: archives (`.zip`, `.rar`, `.7z`) created in temp/public dirs
- Cloud-storage or paste-site uploads; DNS tunneling; long-lived TLS to rare ASNs
- Access to data stores outside a user's normal pattern; mass file reads
- DLP alerts (PII/PHI/PCI patterns leaving the org)

## 2. Containment
1. Identify and isolate the source host(s) and account(s); disable compromised accounts.
2. Block the exfil channel (destination IP/domain, cloud app, port) at egress.
3. Preserve volatile data and network captures before remediation.
4. Revoke tokens/API keys that may have been used.

## 3. Investigation
- Reconstruct the data flow: source → staging → channel → destination.
- Quantify what left: which records/files, classification, volume (PCAP, proxy, NetFlow, DLP logs).
- Determine access path and dwell time; correlate auth logs, EDR, file-access auditing.
- Distinguish insider vs external actor; check for lateral movement and additional footholds.
- ATT&CK mapping: T1041 (Exfil over C2), T1567 (Exfil to Web Service), T1048 (Exfil over Alt Protocol), T1530 (Data from Cloud Storage).

## 4. Eradication & Recovery
- Remove attacker access/persistence; rotate all potentially exposed secrets.
- Close the access path (misconfig, vuln, over-permissioned account/role).
- Restore tightened access controls; enable/expand egress monitoring + DLP.

## 5. Post-incident
- Impact assessment for breach-notification decisions (regulatory counsel).
- Report with exact data scope, timeline, root cause, and IOCs.
- Harden: least-privilege on data stores, egress filtering, DLP tuning, UEBA.

## Key data sources
Proxy/web gateway logs, firewall/NetFlow, DLP, cloud audit logs (CloudTrail/Entra/GCP), EDR file-access, Windows object-access auditing (Event ID 4663), email gateway.
