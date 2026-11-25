#!/usr/bin/env python3
"""Launch or collect the physical-iPhone experiment using Apple's device tool."""
import argparse
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('action', choices=['launch', 'collect'])
p.add_argument('--device', required=True)
p.add_argument('--server', default='http://192.168.1.127:8788')
p.add_argument('--account-token-file', type=Path, default=Path('/private/tmp/multiaudit-mobile-owner-server/account-token.txt'))
p.add_argument('--files', default='10')
p.add_argument('--schemes', default='MultiAudit,Xu,Yu')
p.add_argument('--repeats', type=int, default=30)
p.add_argument('--warmups', type=int, default=3)
p.add_argument('--verify', choices=['0', '1'], default='1')
p.add_argument('--output', type=Path, default=Path('/private/tmp/multiaudit-iphone-results.json'))
a = p.parse_args()
cmd = ['xcrun', 'devicectl', 'device']
if a.action == 'launch':
    environment = {'MA_URL': a.server, 'MA_ACCOUNT_TOKEN': a.account_token_file.read_text().strip(),
                   'MA_AUTORUN': '1', 'MA_REPEATS': str(a.repeats), 'MA_WARMUPS': str(a.warmups),
                   'MA_FILES': a.files, 'MA_SCHEMES': a.schemes, 'MA_VERIFY': a.verify}
    cmd += ['process', 'launch', '--device', a.device, '--terminate-existing',
            '--environment-variables', json.dumps(environment), 'org.multiaudit.client']
else:
    a.output.parent.mkdir(parents=True, exist_ok=True)
    cmd += ['copy', 'from', '--device', a.device, '--domain-type', 'appDataContainer',
            '--domain-identifier', 'org.multiaudit.client', '--source', 'Documents/multiaudit-results.json',
            '--destination', str(a.output)]
completed = subprocess.run(cmd)
if completed.returncode:
    raise SystemExit(completed.returncode)
if a.action == 'collect':
    report = json.loads(a.output.read_text())
    print(json.dumps({'platform': report['platform'], 'model': report['model'],
                      'store_files': len(report.get('stores', [])), 'audit_rounds': len(report['records']),
                      'failure': report.get('failureReason')}, indent=2))
