# Forensics Guide: Disk Acquisition

**Principle:** Acquire a forensically sound copy, preserve integrity (hashing), and document chain of custody. Work from the copy — never the original.

## Order of volatility
Capture most-volatile first: **memory → network state → running processes → disk → archival media**. (See `memory-acquisition.md` for RAM.)

## Bitwise (physical) vs logical copy
- **Bitwise/physical (`dd`, E01):** every sector incl. slack/unallocated/deleted. Use for full investigations and deleted-file recovery.
- **Logical:** specific files/volumes only. Faster; use when full imaging is impractical or scope is narrow (and document the limitation).

## Tools
- **FTK Imager** (Windows) — image to E01 with built-in hashing + write-blocking workflow.
- **dd / dcfldd / dc3dd** (Linux) — `dc3dd` adds progress + on-the-fly hashing.
- **Hardware write blocker** when imaging physical media.

## Procedure (physical disk, Linux)
```bash
# Identify the source (verify it's the evidence disk, not your OS disk!)
lsblk

# Image with hashing (dc3dd), writing a log
sudo dc3dd if=/dev/sdX of=/evidence/CASE123-disk.dd \
    hash=sha256 log=/evidence/CASE123-disk.log

# Verify the image hash matches the source
sha256sum /evidence/CASE123-disk.dd
```

## Chain of custody (record for every item)
| Field | Example |
|-------|---------|
| Case / item ID | CASE123 / DISK-01 |
| Description | 500GB Samsung SSD S/N ... |
| Acquired by | Garfield McLeod |
| Date/time (UTC) | 2026-06-19T14:00Z |
| Acquisition tool + version | dc3dd 7.x |
| Source hash (SHA-256) | ... |
| Image hash (SHA-256) | ... (must match) |
| Storage location | Evidence locker / encrypted volume |
| Transfers | who → who, when |

## Do / Don't
- **Do** hash before and after; record both. A mismatch invalidates the image.
- **Do** use a write blocker on originals.
- **Don't** mount the original read-write or boot from it.
- **Don't** store evidence on the same media as analysis output.
