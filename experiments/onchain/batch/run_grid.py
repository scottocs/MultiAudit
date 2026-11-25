#!/usr/bin/env python3
"""Run real EVM fixture transactions with a bounded local process pool."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import platform
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SCHEMES = ['XuTIFS26', 'YuTC25', 'MultiAudit']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixtures', type=Path)
    parser.add_argument('compiled', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--evm', type=Path, help='use Geth offline transition tool instead of Ganache')
    parser.add_argument('--smoke-metadata', type=Path)
    parser.add_argument('--exclude', default='', help='comma-separated SCHEME:COUNT cases already running')
    args = parser.parse_args()
    fixtures, compiled, output = [p.resolve() for p in [args.fixtures, args.compiled, args.output]]
    if args.workers < 1:
        parser.error('--workers must be positive')
    output.mkdir(parents=True, exist_ok=True)

    native_prefix = []
    if platform.system() == 'Darwin':
        probe = subprocess.run(['arch', '-arm64', 'node', '-p', 'process.arch'], capture_output=True, text=True)
        if probe.returncode == 0 and probe.stdout.strip() == 'arm64':
            native_prefix = ['arch', '-arm64']
    print('Node execution:', 'native arm64' if native_prefix else 'default architecture', flush=True)

    def run(case):
        scheme, m = case
        part = output / 'parts' / f'm{m}-{scheme}'
        part.mkdir(parents=True, exist_ok=True)
        fixture = fixtures / f'{scheme}-m{m}.json'
        runner = 'experiments/onchain/batch/run_transition.cjs' if args.evm else 'experiments/onchain/batch/run.cjs'
        command = native_prefix + ['node', '--max-old-space-size=4096', runner,
                   str(fixture), str(compiled), str(part), '--scheme', scheme]
        if args.evm:
            command += ['--evm', str(args.evm.resolve())]
            if args.smoke_metadata:
                command += ['--smoke-metadata', str(args.smoke_metadata.resolve())]
        with (part / 'run.log').open('w') as log:
            subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
        metadata = json.loads((part / 'metadata.json').read_text())
        records = json.loads((part / 'records.json').read_text())
        assert metadata['complete'] and len(records) == 5 and len(metadata['negative_checks']) == 3
        return scheme, m

    # Start large fixtures first to reduce the final long-running worker tail.
    excluded = set(args.exclude.split(','))
    cases = [(scheme, m) for m in [40, 30, 20, 10] for scheme in SCHEMES if f'{scheme}:{m}' not in excluded]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        jobs = [pool.submit(run, case) for case in cases]
        for completed, future in enumerate(as_completed(jobs), 1):
            scheme, m = future.result()
            print(f'Completed {scheme} m={m}: {completed}/{len(cases)} configurations, {completed*5}/{len(cases)*5} receipts', flush=True)


if __name__ == '__main__':
    main()
