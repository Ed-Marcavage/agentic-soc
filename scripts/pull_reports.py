#!/usr/bin/env python3
"""List recent threat reports about attacker agents from Papers With Code Cyber.

Reads the public catalog API (no key needed) and writes the candidate reports
for one week's skill update. A person or agent then reads each source report
and decides what changes; see MAINTAINING.md.

Usage: python3 scripts/pull_reports.py --since 2026-11-08 [--out reports/2026-11-15.json]
"""
import argparse
import json
import pathlib
import sys
import urllib.request
from datetime import date

BASE = "https://paperswithcode-cyber.com"
HEADERS = {"User-Agent": "agentic-soc-pull-reports/0.1"}
REPORT_TYPES = {"malware-or-threat-intel", "incident-postmortem", "detection-engineering"}
ROOT = pathlib.Path(__file__).resolve().parent.parent


def get(path):
    req = urllib.request.Request(BASE + path, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def all_posts():
    rows, offset = [], 0
    while True:
        page = get(f"/api/v1/catalog/papers?kind=post&limit=25&offset={offset}")
        rows += page["results"]
        offset += 25
        if not page["results"] or offset >= page["total"]:
            return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", required=True, help="keep reports published on or after this date (YYYY-MM-DD)")
    ap.add_argument("--min-agent-relevance", type=int, default=2)
    ap.add_argument("--out", help="output file (default reports/<today>.json)")
    args = ap.parse_args()

    watch = [w.strip().lower() for w in (ROOT / "reports" / "watchlist.txt").read_text().splitlines()
             if w.strip() and not w.startswith("#")]
    picked = []
    for row in all_posts():
        post = row.get("post") or {}
        tools = [e["name"] for e in post.get("entities") or [] if e.get("type") == "tool"]
        on_watchlist = [t for t in tools if t.lower() in watch]
        is_report = (post.get("post_type") in REPORT_TYPES
                     or "intrusion-campaigns" in (post.get("subtopics") or []))
        if not is_report:
            continue
        if (post.get("agent_relevance") or 0) < args.min_agent_relevance and not on_watchlist:
            continue
        detail = get(f"/api/v1/papers/{row['paper_id']}")
        published = (detail.get("published") or "")[:10]
        if published < args.since:
            continue
        picked.append({
            "catalog_id": row["paper_id"],
            "catalog_url": f"{BASE}/paper/{row['paper_id']}",
            "source_url": row["source_url"],
            "publisher": row.get("publisher"),
            "title": row["title"],
            "published": published,
            "post_type": post.get("post_type"),
            "subtopics": post.get("subtopics") or [],
            "agent_relevance": post.get("agent_relevance"),
            "tools": tools,
            "watchlist_match": on_watchlist,
            "summary": post.get("tldr"),
            "caveat": post.get("caveat"),
        })
    picked.sort(key=lambda r: r["published"], reverse=True)

    out = pathlib.Path(args.out) if args.out else ROOT / "reports" / f"{date.today().isoformat()}.json"
    out.write_text(json.dumps({"since": args.since, "pulled": date.today().isoformat(),
                               "reports": picked}, indent=1, ensure_ascii=False) + "\n")
    print(f"{len(picked)} reports since {args.since} written to {out}", file=sys.stderr)
    for r in picked:
        print(f"{r['published']}  {r['publisher'] or '?':<12}  {r['title'][:90]}")


if __name__ == "__main__":
    main()
