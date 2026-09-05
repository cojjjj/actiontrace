import argparse
import json
from pathlib import Path
import sys

from .analyzer import Analyzer
from .render import html_report, sarif, terminal


def main(argv=None):
    parser = argparse.ArgumentParser(description="Trace trust boundaries in local GitHub Actions workflows without executing them.")
    parser.add_argument("path", type=Path, help="Repository directory or individual workflow YAML")
    parser.add_argument("--root", type=Path, help="Repository root for a single workflow (required to resolve local actions correctly)")
    parser.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=["high", "medium", "low", "none"], default="high")
    parser.add_argument("--strict", action="store_true", help="Treat coverage warnings as analysis errors")
    args = parser.parse_args(argv)
    try:
        path = args.path.resolve()
        if not path.exists():
            raise ValueError(f"Input does not exist: {args.path}")
        if path.is_file():
            root = args.root.resolve() if args.root else (path.parent.parent.parent if path.parent.name == "workflows" and path.parent.parent.name == ".github" else path.parent)
            report = Analyzer(root).scan([path])
        else:
            if args.root and args.root.resolve() != path:
                raise ValueError("--root must match the input directory when scanning a repository")
            report = Analyzer(path).scan()
        if args.format == "text":
            rendered = terminal(report)
        elif args.format == "html":
            rendered = html_report(report)
        else:
            rendered = json.dumps(sarif(report) if args.format == "sarif" else report.to_dict(), indent=2) + "\n"
        if args.output:
            # Never overwrite an analyzed workflow/action, including via symlink.
            if args.output.resolve() in {p.resolve() for p in (path.rglob("*.yml") if path.is_dir() else [path])} or args.output.suffix.lower() in {".yml", ".yaml"}:
                raise ValueError("Report output must not overwrite YAML input")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        if any(d["level"] == "error" or args.strict for d in report.diagnostics):
            return 2
        rank = {"none": 99, "high": 3, "medium": 2, "low": 1}
        return int(any(rank[f.severity] >= rank[args.fail_on] for f in report.findings))
    except (OSError, ValueError) as exc:
        print(f"actiontrace: {exc}", file=sys.stderr)
        return 2
