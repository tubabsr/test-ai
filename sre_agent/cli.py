"""Command-line entry point.

Example:
    python -m sre_agent.cli analyze --namespace shop --workload checkout --minutes 30 --out rca.md
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .rca import render_markdown
from .service import Settings, run_analysis


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="sre-agent", description="Evidence-based Kubernetes RCA")
    sub = parser.add_subparsers(dest="cmd", required=True)

    analyze = sub.add_parser("analyze", help="analyze a namespace and workload over a time window")
    analyze.add_argument("--namespace", required=True)
    analyze.add_argument("--workload", required=True, help="Deployment name, used in suggested commands")
    analyze.add_argument("--minutes", type=int, default=30)
    analyze.add_argument("--selector", help='extra LogQL matcher, for example app="checkout"')
    analyze.add_argument("--format", choices=["markdown", "json"], default="markdown")
    analyze.add_argument("--out", help="write the report to this file instead of stdout")

    args = parser.parse_args(argv)

    try:
        report = run_analysis(Settings.from_env(), namespace=args.namespace, workload=args.workload,
                              minutes=args.minutes, selector=args.selector)
    except ValueError as exc:
        print(f"invalid input: {exc}", file=sys.stderr)
        return 2

    if args.format == "markdown":
        text = render_markdown(report)
    else:
        text = json.dumps(asdict(report), default=str, indent=2)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
