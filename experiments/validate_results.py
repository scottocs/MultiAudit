#!/usr/bin/env python3
"""Validate the fixed-file-size experiment against its raw observations."""
import csv
import hashlib
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from measurement_provenance import verify_sources

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / 'experiments/results/paper/runtime.csv'
SCHEMES = ['XuTIFS26', 'ZhangTPDS23', 'YuTC25', 'MiaoSCIS2026', 'MultiAudit']


def read_csv(path):
    with path.open(newline='') as stream:
        return list(csv.DictReader(stream))


def validate(path=DEFAULT):
    provenance = json.loads((path.parent / 'native_provenance.json').read_text())
    verify_sources(provenance['source_sha256'], path.parent / provenance['archive'], provenance['sha256'])
    rows = read_csv(path)
    meta = json.loads(Path(str(path) + '.meta.json').read_text())
    assert meta['profile'] == 'file-count'
    assert (meta['B_MB'], meta['s'], meta['c'], meta['n']) == (10, 80, 690, 3907)
    assert meta['m_scan'] == [10, 20, 30, 40] and meta['complete'] is True
    assert meta['online_repeats'] == 30 and meta['goarch'] == 'arm64'
    assert meta['multiaudit_protocol'] == 'multiaudit/compact-merkle-shplonk/v2-unmasked'
    assert meta['arithmetic_backend'] == 'shared-delayed-reduction/v1'
    assert meta['storage_backend'] == 'owned-scalar-arena/v1'
    expected = {(m, name, phase) for m in meta['m_scan'] for name in SCHEMES
                for phase in ['Store', 'ProofGen', 'Verify']}
    raw = read_csv(Path(str(path) + '.samples.csv'))
    groups = defaultdict(list)
    order = defaultdict(dict)
    for record in raw:
        assert record['ok'] == 'true' and record['measurement_source'] == 'measured'
        assert (record['B_MB'], record['s'], record['c']) == ('10', '80', '690')
        value = float(record['milliseconds'])
        assert math.isfinite(value) and value > 0
        key = (int(record['m']), record['scheme'], record['phase'])
        groups[key].append(record)
        if record['phase'] == 'ProofGen':
            order[(record['m'], record['repeat'])][record['scheme']] = int(record['order_position'])
    assert set(groups) == expected and len(raw) == 1220
    for positions in order.values():
        assert sorted(positions.values()) == list(range(5))
    seen = set()
    for row in rows:
        key = (int(row['m']), row['scheme'], row['phase'])
        assert key not in seen
        seen.add(key)
        assert row['scenario'] == 'vary_m' and row['variable'] == 'm'
        assert (row['B_MB'], row['s'], row['c'], row['n']) == ('10', '80', '690', '3907')
        assert row['ok'] == 'true' and row['measurement_source'] == 'measured'
        native = (3907 * 80, 1) if row['scheme'] == 'MiaoSCIS2026' else (3907, 80)
        assert (int(row['native_blocks']), int(row['native_sectors'])) == native
        assert int(row['encoded_bytes_per_file']) == 10_001_920
        assert int(row['challenged_bytes_per_file']) == 690 * native[1] * 32
        records = groups[key]
        count = 1 if row['phase'] == 'Store' else 30
        assert int(row['repeats']) == len(records) == count
        assert sorted(int(r['repeat']) for r in records) == list(range(1, count + 1))
        values = [float(r['milliseconds']) for r in records]
        assert abs(statistics.median(values) - float(row['milliseconds'])) < 2e-6
        if count > 1:
            quartiles = statistics.quantiles(values, n=4, method='inclusive')
            for actual, saved in [(statistics.stdev(values), row['milliseconds_stddev']),
                                  (quartiles[0], row['p25_ms']), (quartiles[2], row['p75_ms'])]:
                assert abs(actual - float(saved)) < 2e-6
        else:
            assert row['milliseconds_stddev'] == ''
    assert seen == expected and len(rows) == 60
    return rows, meta


def validate_response(path):
    meta = json.loads(Path(str(path) + '.meta.json').read_text())
    assert (meta['m'], meta['n'], meta['s'], meta['c'], meta['repeats']) == (40, 3907, 80, 690, 30)
    assert meta['protocol'] == 'multiaudit/compact-merkle-shplonk/v2-unmasked' and meta['goarch'] == 'arm64' and meta['complete'] is True
    assert (meta['g1_bytes'], meta['scalar_bytes'], meta['digest_bytes']) == (64, 32, 32)
    rows = read_csv(path)
    assert sorted(int(r['repeat']) for r in rows) == list(range(1, 31))
    assert len({r['proof_sha256'] for r in rows}) == 30
    for row in rows:
        assert row['ok'] == 'true' and row['c'] == '690'
        assert int(row['wire_bytes']) == 172 + (40 * 690 + 2) * 64 + 40 * 32 + int(row['auxiliary_hashes']) * 32
    return rows


if __name__ == '__main__':
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    rows, meta = validate(path)
    responses = validate_response(path.parent / 'response.csv')
    files = [path, Path(str(path) + '.samples.csv'), path.parent / 'response.csv']
    report = {'fixtures': 20, 'online_audits': 600, 'response_measurements': len(responses),
              'summary_rows': len(rows), 'all_proofs_accepted': True,
              'statistics_match_raw_samples': True,
              'sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
    destination = path.parent / 'validation.json'
    saved = json.loads(destination.read_text()) if destination.exists() else {}
    saved.update(report)
    destination.write_text(json.dumps(saved, indent=2) + '\n')
    print(json.dumps(report, indent=2))
