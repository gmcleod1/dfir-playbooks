# Forensics Guide: Memory Acquisition & Analysis

**Why:** RAM holds running processes, injected code, network connections, decrypted strings, and (sometimes) encryption keys — gone on reboot. Capture **before** isolation steps that risk a restart.

## Acquisition

### Windows
- **WinPmem** (`winpmem.exe -o C:\evidence\mem.raw`) or **DumpIt** or **FTK Imager** (Capture Memory).
- Write to external/evidence media, not the suspect disk where possible.
- Record: tool+version, time (UTC), hostname, RAM size, acquirer, SHA-256 of the dump.

### Linux
- **AVML** (`./avml mem.lime`) or LiME kernel module.

## Verify integrity
```bash
sha256sum mem.raw    # record in the case file / chain of custody
```

## Analysis with Volatility 3
```bash
# Identify processes
vol -f mem.raw windows.pslist
vol -f mem.raw windows.pstree          # parent/child chains

# Hidden / unlinked processes
vol -f mem.raw windows.psscan

# Network connections
vol -f mem.raw windows.netscan

# Command lines (what was actually run)
vol -f mem.raw windows.cmdline

# Injected / malicious code
vol -f mem.raw windows.malfind

# Loaded DLLs / handles for a suspect PID
vol -f mem.raw windows.dlllist --pid <PID>

# Dump a suspect process for static analysis
vol -f mem.raw windows.dumpfiles --pid <PID>
```

## What to look for
- Processes with no parent or odd parents (e.g. `winword.exe` → `powershell.exe`)
- `malfind` hits (RWX private memory = likely injection)
- Network connections to rare/known-bad destinations
- Unsigned DLLs, suspicious command lines, masquerading process names

## Hand-off
Carve suspect binaries → analyze in `malware-analysis-lab`. Feed extracted C2/host IOCs into `threat-intel-tools`.
