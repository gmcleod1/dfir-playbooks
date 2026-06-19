#!/usr/bin/env python3
"""
timeline-builder.py - Correlate artifacts from multiple sources into one timeline.

Ingests:
  - triage-collector.ps1 JSON (process creation times, security/PowerShell events)
  - generic CSV artifact exports (e.g. Eric Zimmerman tools) via --csv NAME=FILE,
    where each CSV has a timestamp column (auto-detected or set with --time-col)

Emits a single chronological CSV: timestamp, source, event, detail.

Usage:
    python timeline-builder.py --triage triage-HOST.json --output timeline.csv
    python timeline-builder.py --csv prefetch=PECmd.csv --csv mft=MFTECmd.csv -o tl.csv
"""
import argparse
import csv
import json
import sys
from datetime import datetime

# Column names commonly holding the primary timestamp in forensic CSVs.
TIME_HINTS = ["lastrun", "runtime", "timestamp", "time", "created", "date",
              "created0x10", "lastmodified", "executiontime", "starttime"]


def parse_ts(value):
    """Best-effort parse of common timestamp formats; return ISO string or None."""
    if not value:
        return None
    value = str(value).strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(value, fmt).isoformat()
        except ValueError:
            continue
    # Last resort: fromisoformat
    try:
        return datetime.fromisoformat(value).isoformat()
    except ValueError:
        return None


def from_triage(path, rows):
    with open(path, encoding="utf-8-sig") as fh:
        data = json.load(fh)
    host = data.get("meta", {}).get("hostname", "?")

    for p in data.get("processes", []):
        ts = parse_ts(p.get("created"))
        if ts:
            rows.append((ts, f"process@{host}",
                         f"proc {p.get('name')} (pid {p.get('pid')})",
                         p.get("command_line") or p.get("path") or ""))
    for ev in data.get("recent_security_events", []):
        rows.append((ev.get("time"), f"security@{host}",
                     f"EventID {ev.get('id')}", ev.get("msg", "")))
    for ev in data.get("recent_powershell", []):
        rows.append((ev.get("time"), f"powershell@{host}",
                     f"EventID {ev.get('id')}", ev.get("msg", "")))


def find_time_col(fieldnames, override):
    if override:
        return override
    lowered = {f.lower(): f for f in fieldnames}
    for hint in TIME_HINTS:
        for low, original in lowered.items():
            if hint in low:
                return original
    return None


def from_csv(name, path, rows, time_col_override):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        time_col = find_time_col(reader.fieldnames or [], time_col_override)
        if not time_col:
            print(f"[!] {path}: no timestamp column found "
                  f"(use --time-col). Columns: {reader.fieldnames}", file=sys.stderr)
            return
        for row in reader:
            ts = parse_ts(row.get(time_col))
            if not ts:
                continue
            detail = "; ".join(f"{k}={v}" for k, v in list(row.items())[:4] if v)
            rows.append((ts, name, time_col, detail))


def main():
    parser = argparse.ArgumentParser(description="Build a correlated forensic timeline.")
    parser.add_argument("--triage", help="triage-collector.ps1 JSON file")
    parser.add_argument("--csv", action="append", default=[],
                        help="NAME=FILE for a CSV artifact export (repeatable)")
    parser.add_argument("--time-col", help="Force this column name as the timestamp")
    parser.add_argument("--output", "-o", default="timeline.csv")
    args = parser.parse_args()

    rows = []
    if args.triage:
        from_triage(args.triage, rows)
    for spec in args.csv:
        if "=" not in spec:
            parser.error(f"--csv expects NAME=FILE, got '{spec}'")
        name, path = spec.split("=", 1)
        from_csv(name, path, rows, args.time_col)

    if not rows:
        sys.exit("No timeline rows produced. Provide --triage and/or --csv inputs.")

    rows.sort(key=lambda r: r[0])
    with open(args.output, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "source", "event", "detail"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} timeline rows -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
