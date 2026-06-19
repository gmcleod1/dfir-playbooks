# Playbook: Ransomware Incident Response

**Scope:** Active or suspected ransomware (file encryption, ransom note, mass file changes).
**Framework:** NIST SP 800-61r2 (Prepare → Detect & Analyze → Contain/Eradicate/Recover → Post-Incident).
**Severity:** Critical by default.

> Goal: contain encryption spread and preserve evidence **before** wiping/restoring. Do not power off systems if memory may hold keys — isolate instead.

## 1. Detection indicators
- Mass file modifications / new extensions (e.g. `.locked`, random) in short window
- Ransom note files (`*README*.txt`, `*DECRYPT*`) across shares
- Shadow copy deletion (`vssadmin delete shadows`), backup tampering
- Spike in file-rename/write events; EDR alert on known ransomware family
- Disabled security tooling, new admin accounts, lateral SMB activity

## 2. Containment (act fast, preserve evidence)
1. **Isolate** affected hosts from the network (disable switch port / EDR network-contain). **Do not shut down** — capture memory first (see `forensics/memory-acquisition.md`).
2. Disable affected accounts and rotate exposed credentials (esp. domain admin, service accounts).
3. Block known C2 IOCs at firewall/proxy/DNS.
4. Protect backups: take them offline; verify they are not encrypted; halt replication to backups.
5. Identify patient zero and initial access vector early (phishing? RDP? exposed service?).

## 3. Investigation
- Memory capture → identify ransomware process, injected code, possible keys.
- Build timeline (`scripts/timeline-builder.py`): initial access → execution → privilege escalation → lateral movement → encryption.
- Determine scope: which hosts/shares encrypted, what data classes, exfil evidence (double-extortion).
- Identify the family (note text, extension, IOC lookup) → known decryptors? (e.g. No More Ransom).
- Map to MITRE ATT&CK (e.g. T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery, T1021 Lateral Movement).

## 4. Eradication & Recovery
- Rebuild from known-good images where possible; do not trust cleaned hosts blindly.
- Restore data from verified-clean offline backups after entry vector is closed.
- Patch/close the initial access vector; enforce MFA; remove attacker persistence.
- Phased reconnection with monitoring; watch for re-encryption attempts.

## 5. Post-incident
- Final report (use `reports/ir-case-template.md`): timeline, scope, impact, root cause, IOCs.
- Lessons learned; update detections (backup-deletion alerts, RDP exposure, EDR tamper alerts).
- Legal/regulatory: breach notification obligations; preserve evidence for potential law enforcement.

## Do / Don't
- **Do** capture volatile memory before isolation actions that risk reboot.
- **Do** preserve a copy of an encrypted file + ransom note (needed for decryptor matching).
- **Don't** pay or negotiate without legal/exec/law-enforcement involvement.
- **Don't** reboot or run AV "clean" before evidence acquisition.
