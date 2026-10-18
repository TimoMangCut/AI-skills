from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .llm import LocalModelError
from .orchestrator import analyze_repositories


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="localsec", description="AI-only manual reconnaissance and security architecture review for local repositories")
    parser.add_argument("--version", action="version", version=f"localsec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="run fixed AI skills that manually inspect local repository files")
    analyze.add_argument("--repo", action="append", default=[], help="repository path; repeat for multiple repos")
    analyze.add_argument("--repos", nargs="+", default=[], help="repository paths")
    analyze.add_argument("--config", default=None, help="TOML config path (defaults to ./localsec.toml if it exists)")
    analyze.add_argument("--out", default=None, help="documents output directory (default from config)")
    analyze.add_argument("--workdir", default=None, help="run logs/evidence directory (default from config)")
    analyze.add_argument("--json", action="store_true", help="print machine-readable run summary")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "analyze":
        parser.error("Unsupported command")
    repos = list(args.repo) + list(args.repos)
    if not repos:
        parser.error("Pass at least one --repo PATH or --repos PATH [PATH ...]")
    config_path = args.config
    if config_path is None and Path("localsec.toml").exists():
        config_path = "localsec.toml"
    try:
        cfg = load_config(config_path)
        result = analyze_repositories(repos, cfg=cfg, output_dir=args.out, work_dir=args.workdir, use_llm=True)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            cov = result["system_coverage"]
            print(f"Run ID:         {result['run_id']}")
            print(f"Documents:      {result['output_dir']}")
            print(f"Work artifacts: {result['work_dir']}")
            print(f"Workflow:       {cov['workflow_status']}")
            print(f"Analysis mode:  {cov['analysis_mode']}")
            print(f"Coverage:       {cov['coverage_status']} (non-exhaustive by design)")
            print(f"Security state: {cov['security_posture']}")
            print(f"Local model:    {cov['llm']['model']}")
            for repo in cov["repos"]:
                print(f"  - {repo['repo_name']}: {repo['workflow_status']} ({repo['unique_files_read']} files read, {repo['evidence_count']} evidence records)")
            print(f"Cross-repo:     {cov['cross_repo_review_status']}")
        return 0 if result["system_coverage"]["workflow_status"] == "completed" else 2
    except (ValueError, OSError, LocalModelError) as exc:
        print(f"localsec: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
