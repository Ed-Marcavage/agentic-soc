#!/usr/bin/env python3
"""Summarise request timing per identity in CloudTrail or web access logs.

This script only counts. It does not decide whether anything is an attack;
that judgement belongs to whoever reads the output and the raw events.

Usage: python3 cadence.py LOGFILE [LOGFILE ...] [--json] [--min-events N]

Input formats, detected per file:
  - CloudTrail JSON: {"Records": [...]} or one event per line
  - Web access log in combined format
"""
import argparse
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

BURST_GAP = 2.0  # seconds; requests closer than this belong to one burst
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?'
)
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def parse_cloudtrail_event(e):
    ident = e.get("userIdentity") or {}
    if ident.get("accountId") == "anonymous" or ident.get("principalId") == "anonymous":
        who = "anonymous@" + str(e.get("sourceIPAddress", "?"))
    else:
        session = (ident.get("arn") or "").rsplit("/", 1)[-1]
        principal = ident.get("principalId")
        if principal in ("", "Anonymous"):
            principal = None
        who = (ident.get("accessKeyId") or ident.get("arn") or principal
               or "unauthenticated@" + str(e.get("sourceIPAddress", "?")))
        if session and session not in who:
            who = f"{who} ({session})"
    ts = datetime.strptime(e["eventTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return {
        "who": who,
        "ts": ts.timestamp(),
        "action": f'{e.get("eventSource", "").split(".")[0]}:{e.get("eventName", "?")}',
        "error": e.get("errorCode") or "",
        "ip": e.get("sourceIPAddress", ""),
        "ua": e.get("userAgent", ""),
        "target": json.dumps(e.get("requestParameters") or {}, sort_keys=True)[:200],
        "write": not e.get("readOnly", True),
    }


def parse_file(path):
    events, skipped = [], 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    stripped = text.lstrip()
    if stripped.startswith("{") and '"Records"' in stripped[:200]:
        for e in json.loads(text).get("Records", []):
            events.append(parse_cloudtrail_event(e))
        return events, skipped
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("{"):
                events.append(parse_cloudtrail_event(json.loads(line)))
                continue
            m = ACCESS_RE.match(line)
            if not m:
                skipped += 1
                continue
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
            status = int(m["status"])
            events.append({
                "who": m["ip"],
                "ts": ts.timestamp(),
                "action": f'{m["method"]} {m["path"].split("?")[0]}',
                "error": str(status) if status >= 400 else "",
                "ip": m["ip"],
                "ua": m["ua"] or "",
                "target": m["path"],
                "write": m["method"] in WRITE_METHODS,
            })
        except (ValueError, KeyError):
            skipped += 1
    return events, skipped


def summarise(who, evs):
    evs.sort(key=lambda e: e["ts"])
    gaps = [b["ts"] - a["ts"] for a, b in zip(evs, evs[1:])]
    bursts, pauses, size = [], [], 1
    for g in gaps:
        if g <= BURST_GAP:
            size += 1
        else:
            bursts.append(size)
            pauses.append(g)
            size = 1
    bursts.append(size)
    errors = [e for e in evs if e["error"]]
    # corrected retry: a failure, then the same action succeeding within 120 seconds
    corrected = 0
    for i, e in enumerate(evs):
        if not e["error"]:
            continue
        for later in evs[i + 1:]:
            if later["ts"] - e["ts"] > 120:
                break
            if later["action"] == e["action"] and not later["error"]:
                corrected += 1
                break
    # read of the same target right after a successful write
    verified = sum(
        1 for a, b in zip(evs, evs[1:])
        if a["write"] and not a["error"] and not b["write"]
        and b["target"].split("?")[0] == a["target"].split("?")[0]
    )
    in_band = [p for p in pauses if 20 <= p <= 40]
    return {
        "identity": who,
        "events": len(evs),
        "first": datetime.fromtimestamp(evs[0]["ts"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "last": datetime.fromtimestamp(evs[-1]["ts"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "span_minutes": round((evs[-1]["ts"] - evs[0]["ts"]) / 60, 1),
        "source_ips": sorted({e["ip"] for e in evs if e["ip"]})[:5],
        "user_agents": [u for u, _ in Counter(e["ua"] for e in evs if e["ua"]).most_common(3)],
        "distinct_actions": len({e["action"] for e in evs}),
        "top_actions": Counter(e["action"] for e in evs).most_common(5),
        "error_rate": round(len(errors) / len(evs), 2),
        "top_errors": Counter(e["error"] for e in errors).most_common(3),
        "bursts": len(bursts),
        "burst_size_median": statistics.median(bursts),
        "burst_size_max": max(bursts),
        "pause_median_s": round(statistics.median(pauses), 1) if pauses else None,
        "pauses_20_to_40s": len(in_band),
        "pauses_20_to_40s_share": round(len(in_band) / len(pauses), 2) if pauses else None,
        "corrected_retries": corrected,
        "writes_then_read_back": verified,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--min-events", type=int, default=5, help="skip identities with fewer events (default 5)")
    args = ap.parse_args()

    by_who, skipped = defaultdict(list), 0
    for path in args.logs:
        evs, sk = parse_file(path)
        skipped += sk
        for e in evs:
            by_who[e["who"]].append(e)
    rows = [summarise(w, evs) for w, evs in by_who.items() if len(evs) >= args.min_events]
    rows.sort(key=lambda r: (-(r["pauses_20_to_40s"] or 0), -r["error_rate"], -r["events"]))
    small = sum(1 for evs in by_who.values() if len(evs) < args.min_events)

    if args.json:
        json.dump({"identities": rows, "skipped_lines": skipped, "identities_below_min": small}, sys.stdout, indent=1)
        print()
        return
    print(f"{len(rows)} identities with at least {args.min_events} events; "
          f"{small} smaller ones not shown; {skipped} lines not parsed\n")
    for r in rows:
        print(f"== {r['identity']}")
        print(f"   {r['events']} events, {r['first']} to {r['last']} UTC ({r['span_minutes']} min), from {', '.join(r['source_ips']) or 'n/a'}")
        print(f"   user agents: {'; '.join(r['user_agents']) or 'n/a'}")
        print(f"   {r['distinct_actions']} distinct actions; top: {', '.join(f'{a} x{n}' for a, n in r['top_actions'])}")
        print(f"   error rate {r['error_rate']}; top errors: {', '.join(f'{a} x{n}' for a, n in r['top_errors']) or 'none'}")
        print(f"   {r['bursts']} bursts, median size {r['burst_size_median']}, largest {r['burst_size_max']}; "
              f"median pause {r['pause_median_s']} s; pauses of 20-40 s: {r['pauses_20_to_40s']} "
              f"(share {r['pauses_20_to_40s_share']})")
        print(f"   corrected retries: {r['corrected_retries']}; writes then read back: {r['writes_then_read_back']}\n")


if __name__ == "__main__":
    main()
