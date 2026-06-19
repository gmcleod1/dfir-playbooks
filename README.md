# DFIR Playbooks

Structured incident response and forensic procedures for common attack scenarios. Includes disk/memory forensics runbooks, Windows artifact guides, and triage scripts.

## Incident Response Playbooks

Proven procedures for common attack scenarios:

- **Ransomware Response:** Initial detection → containment → investigation → recovery planning
- **Data Exfiltration:** Identifying suspicious network traffic → lateral movement detection → data flow reconstruction
- **Malware Infection:** Compromised system isolation → artifact collection → threat hunting → remediation

Each playbook includes:
- Detection indicators (what to look for)
- Isolation steps (containment)
- Investigation procedures (timeline, scope, impact)
- Hunting rules (for finding similar activity)
- Recovery and hardening steps
- Post-incident review

## Digital Forensics Guides

### Disk Forensics
- Evidence acquisition (bitwise vs logical copy)
- Chain of custody documentation
- File system analysis and timeline reconstruction
- Deleted file recovery
- Partition and volume analysis

### Memory Forensics
- Memory dump acquisition
- Volatility 3 workflow
- Process analysis and suspicious behavior detection
- Network connection extraction
- Injected code identification

### Windows Artifacts
- Registry analysis (UserAssist, RecentDocs, MountedDevices, services)
- Prefetch analysis (program execution history)
- LNK files (shortcut analysis)
- Event Log analysis (logon, service, PowerShell execution)
- Windows Timeline (Win 10+)
- MFT and $UsnJrnl (file activity journal)

## Project Structure

```
dfir-playbooks/
  README.md                       # This file
  playbooks/
    ransomware-ir.md              # Ransomware IR procedure
    data-exfil-ir.md              # Data exfiltration response
    malware-infection-ir.md        # Malware infection response
  forensics/
    disk-acquisition.md           # Evidence collection
    memory-acquisition.md         # Memory dump procedures
    windows-artifact-guide.md     # Registry, Prefetch, LNK, EventLogs
  scripts/
    triage-collector.ps1          # Volatile data collection
    timeline-builder.py           # Event correlation
  reports/
    ir-case-template.md           # IR report template
    timeline-template.md          # Timeline documentation
```

## Key Scripts

### triage-collector.ps1
Collects volatile system data from a live Windows host:
- Running processes and services
- Network connections
- Recently accessed files
- Scheduled tasks
- User activity
- System event logs (last 24 hours)

Output: Timestamped JSON for later analysis

### timeline-builder.py
Correlates artifacts from multiple sources into a unified timeline:
- File system modifications (MFT, $UsnJrnl)
- Registry changes
- Event log entries
- Prefetch execution
- Browser history
- Email activity (if applicable)

Output: Chronological timeline with source and confidence

## Case Workflow

1. **Detect:** Identify suspicious activity or indicator of compromise
2. **Acquire:** Collect evidence (memory, disk, logs, network)
3. **Analyze:** Use forensic tools to extract artifacts
4. **Timeline:** Correlate artifacts chronologically
5. **Investigate:** Determine scope, impact, entry point
6. **Contain:** Isolate affected systems, prevent spread
7. **Eradicate:** Remove malware and close entry points
8. **Recover:** Restore systems and data
9. **Report:** Document findings and recommendations
10. **Improve:** Update IR procedures based on lessons learned

## Resources

- [Windows Forensics Analysis](https://www.sans.org/white-papers/)
- [Volatility Memory Forensics](https://volatility3.readthedocs.io)
- [SANS IR Checklists](https://www.sans.org/reading-room/whitepapers/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ISO/IEC 27035: Incident Management](https://www.iso.org/standard/60803.html)

---

**Last Updated:** June 15, 2026
