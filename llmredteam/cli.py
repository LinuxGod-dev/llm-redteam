from __future__ import annotations

import argparse
import json
import os
import sys

import yaml

from .mutators import MUTATORS
from .report import compare, write_reports
from .runner import load_attacks, run
from .targets import HttpTarget, MockTarget, ScopeError


def _load_cfg(path):
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _build_target(args, cfg):
    if args.target == "mock":
        return MockTarget(hardened=False)
    if args.target == "mock-hardened":
        return MockTarget(hardened=True)
    t = cfg.get("target")
    if not t:
        sys.exit("--target http needs --config with a 'target:' section (see config.example.yaml)")
    return HttpTarget(
        base_url=t["base_url"], model=t["model"], api_key_env=t.get("api_key_env"),
        system_prompt=t.get("system_prompt", ""), tools=t.get("tools", False),
        allowed_hosts=t.get("allowed_hosts"), block_status_codes=t.get("block_status_codes"),
        timeout=t.get("timeout", 60))


def cmd_run(args) -> int:
    cfg = _load_cfg(args.config)
    run_cfg = cfg.get("run", {})
    names = args.mutators.split(",") if args.mutators else run_cfg.get("mutators", list(MUTATORS))
    bad = [n for n in names if n not in MUTATORS]
    if bad:
        sys.exit(f"Unknown mutators: {bad}. Available: {list(MUTATORS)}")
    try:
        target = _build_target(args, cfg)
    except ScopeError as e:
        print(f"SCOPE ERROR: {e}")
        return 2
    attacks = load_attacks(args.attacks, args.category)
    print(f"Target: {target.name} | attacks: {len(attacks)} | mutators: {len(names)}")

    def progress(n, total, aid, m, status):
        print(f"[{n:>3}/{total}] {aid:<8} {m:<16} {status}")

    results = run(target, attacks, names, cfg.get("scoring"), run_cfg.get("delay_seconds", 0), progress)
    s = write_reports(results, target.name, args.out)
    print(f"\nASR: {s['asr_percent']}% ({s['successful_attacks']} successful, "
          f"{s['blocked']} blocked, {s['errors']} errors)")
    for c, v in sorted(s["by_category"].items()):
        print(f"  {c:<26} {v}%")
    print(f"Reports: {os.path.join(args.out, 'report.html')}")
    if args.fail_on_asr is not None and s["asr_percent"] > args.fail_on_asr:
        print(f"FAIL: ASR {s['asr_percent']}% exceeds threshold {args.fail_on_asr}%")
        return 1
    return 0


def cmd_list(args) -> int:
    for a in load_attacks(args.attacks):
        print(f"{a.id:<8} {a.category:<22} {a.severity:<8} {a.title}")
    return 0


def cmd_compare(args) -> int:
    with open(args.baseline, encoding="utf-8") as f:
        b = json.load(f)
    with open(args.guarded, encoding="utf-8") as f:
        g = json.load(f)
    md = compare(b, g)
    print(md)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="llmredteam", description="LLM red-team harness")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run attacks against a target")
    r.add_argument("--target", default="mock", choices=["mock", "mock-hardened", "http"])
    r.add_argument("--config")
    r.add_argument("--attacks", help="directory of attack YAML files")
    r.add_argument("--category", action="append", help="limit to a category (repeatable)")
    r.add_argument("--mutators", help="comma-separated list")
    r.add_argument("--out", default="reports/run")
    r.add_argument("--fail-on-asr", type=float, help="exit 1 if ASR%% exceeds this (CI gate)")
    r.set_defaults(fn=cmd_run)
    l = sub.add_parser("list", help="list attacks")
    l.add_argument("--attacks")
    l.set_defaults(fn=cmd_list)
    c = sub.add_parser("compare", help="compare two results.json files")
    c.add_argument("baseline")
    c.add_argument("guarded")
    c.add_argument("--out")
    c.set_defaults(fn=cmd_compare)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
