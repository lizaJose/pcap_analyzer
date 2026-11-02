#!/usr/bin/env python3
"""PCAP Analyzer: explains in plain language what happens inside a pcap."""
import argparse
import json
import sys
from datetime import datetime

from pcapanalyzer import Analyzer
from pcapanalyzer.menu import Menu
from pcapanalyzer.webserver import serve


def print_text(result, category=None):
    print(f"\nFile: {result['file']}  ({result['packets_analyzed']} relevant packets)\n")
    print("== Summary by host ==")
    for h in result["hosts"]:
        print(f"* {h['ip']}")
        for label, key in (("Sites", "sites"), ("Services", "services"),
                           ("Remote access", "remote"), ("Files", "files")):
            if h[key]:
                print(f"    {label}: {', '.join(h[key])}")
    print("\n== Activity ==")
    for e in result["events"]:
        if category and e["category"].lower() != category.lower():
            continue
        t = datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")
        print(f"[{t}] [{e['protocol']:<6}] {e['summary']}")


def main():
    p = argparse.ArgumentParser(description=__doc__ + " Without arguments it opens the interactive menu.")
    p.add_argument("pcap", nargs="?", help="path to a .pcap / .pcapng file (optional)")
    p.add_argument("--web", action="store_true", help="start the local web server directly (with file upload)")
    p.add_argument("--host", default="127.0.0.1", help="web server interface (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=8000, help="web server port (default 8000)")
    p.add_argument("--text", action="store_true", help="with a pcap: print the report and exit (no menu)")
    p.add_argument("--json", action="store_true", help="with a pcap: print the result as JSON and exit")
    p.add_argument("--category", help="with --text: filter by category (Web, DNS, 'Remote access', Files, Network, Connection)")
    p.add_argument("--tshark", help="path to tshark if it is not in PATH")
    args = p.parse_args()

    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")

    if (args.text or args.json) and not args.pcap:
        p.error("--text and --json require a pcap")

    def analyze(path):
        return Analyzer(path, args.tshark).analyze()

    try:
        if args.text or args.json:
            result = analyze(args.pcap)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print_text(result, args.category)
            if args.web:
                serve(analyze, result, args.host, args.port)
        elif args.web:
            serve(analyze, analyze(args.pcap) if args.pcap else None, args.host, args.port)
        else:
            Menu(args.tshark, args.host, args.port).run(args.pcap)
    except (RuntimeError, FileNotFoundError) as exc:
        sys.exit(f"Error: {exc}")


if __name__ == "__main__":
    main()
