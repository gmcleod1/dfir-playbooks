# Forensics Guide: Windows Artifacts

A map of high-value Windows artifacts for reconstructing attacker and user activity. Pair with `scripts/timeline-builder.py` to correlate them.

## Execution evidence
| Artifact | Location | Tells you |
|----------|----------|-----------|
| Prefetch | `C:\Windows\Prefetch\*.pf` | What executed, how many times, last run times |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | Program execution + SHA-1 of binaries |
| ShimCache | `SYSTEM` hive (AppCompatCache) | Executables present/run (path + size) |
| UserAssist | `NTUSER.DAT` | GUI program launch counts/times per user |
| BAM/DAM | `SYSTEM` hive | Last execution time per app per user |

## Persistence
| Artifact | Location |
|----------|----------|
| Run keys | `…\CurrentVersion\Run`, `RunOnce` (SOFTWARE + NTUSER) |
| Scheduled tasks | `C:\Windows\System32\Tasks\` + `Microsoft-Windows-TaskScheduler/Operational` |
| Services | `SYSTEM\CurrentControlSet\Services` + Event ID 7045 (new service) |
| WMI subscriptions | `OBJECTS.DATA` (root\subscription) |

## User / file activity
| Artifact | Location | Tells you |
|----------|----------|-----------|
| RecentDocs / OpenSaveMRU | `NTUSER.DAT` | Recently opened files |
| LNK / Jump Lists | `…\Recent\`, `…\AutomaticDestinations\` | File access, original paths, volume serials |
| ShellBags | `USRCLASS.DAT` | Folders browsed (incl. deleted/removable) |
| MFT (`$MFT`) | volume root | File create/modify/access/MFT-change (the "$STANDARD_INFORMATION" timestamps) |
| `$UsnJrnl` ($J) | volume | File change journal — creates/renames/deletes |

## Authentication / lateral movement (Security log)
| Event ID | Meaning |
|----------|---------|
| 4624 / 4625 | Logon success / failure (note Logon Type: 3=network, 10=RDP) |
| 4672 | Special privileges assigned (admin logon) |
| 4720 / 4732 | User created / added to privileged group |
| 4698 | Scheduled task created |
| 7045 | Service installed |
| 4688 | Process creation (incl. command line if auditing enabled) |

## PowerShell
- `Microsoft-Windows-PowerShell/Operational` Event ID **4104** = script block logging (deobfuscated content).
- Event ID 4103 = module/pipeline logging.

## Tooling
Eric Zimmerman's tools (PECmd, AmcacheParser, MFTECmd, RECmd, JLECmd, AppCompatCacheParser), Autopsy, KAPE for collection. Normalize outputs to CSV → feed `timeline-builder.py`.
