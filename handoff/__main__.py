"""Command line entry point."""

import argparse
import json
import sys
from pathlib import Path

from .core import make_plan, verify_bundle
from .model import OllamaModel


def main(argv=None):
    parser = argparse.ArgumentParser(description='Local Python source handoff prototype')
    commands = parser.add_subparsers(dest='command', required=True)
    analyze = commands.add_parser('analyze', help='Ask local Qwen for a cited run plan; never executes source')
    analyze.add_argument('source', type=Path)
    analyze.add_argument('--goal', required=True)
    analyze.add_argument('--expect-stdout-line', help='Exact single stdout line to verify, excluding the newline')
    analyze.add_argument('--run-arg', action='append', default=[], help='One reviewed Python CLI argument; repeat in command order')
    analyze.add_argument('--expect-artifact-sha256', help='Independent expected SHA-256 for generated report.html')
    analyze.add_argument('--out', type=Path, required=True)
    verify = commands.add_parser('verify', help='Run only pinned owned samples after fingerprint approval')
    verify.add_argument('plan', type=Path)
    verify.add_argument('--approve', required=True, help='Exact fingerprint shown by analyze')
    verify.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'analyze':
            plan = make_plan(args.source, args.goal, args.out, OllamaModel(), args.expect_stdout_line,
                             args.run_arg, args.expect_artifact_sha256)
            print(json.dumps({'plan': str(args.out), 'fingerprint': plan['fingerprint'],
                              'entry': plan['analysis']['entry'], 'argv': plan['analysis']['argv'],
                              'execution_to_review': plan['execution'],
                              'assertion_to_review': plan['assertion'],
                              'included_files_to_review': plan['hashes'],
                              'inferred_external_dependencies_not_installed': plan['analysis']['dependencies'],
                              'env_names_only': plan['analysis']['env_names'],
                              'evidence': plan['analysis']['evidence'], 'excluded': plan['skipped'],
                              'next_step': 'Review the plan file and type its fingerprint with verify. Generic sources cannot execute yet.'}, ensure_ascii=False, indent=2))
        else:
            result = verify_bundle(args.plan, args.approve, args.out, OllamaModel().explain)
            print(json.dumps({'bundle': str(args.out), 'result': result}, ensure_ascii=False, indent=2))
            if result['status'] != 'passed':
                return 1
    except Exception as exc:
        print(f'ERROR: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
