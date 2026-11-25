#!/usr/bin/env python3
"""Validate physical-phone observations and summarize complete configurations."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics


def summarize(source, destination, expected_repeats=30, sizes=None, schemes=None):
    raw = json.loads(source.read_text())
    assert raw['platform'] == 'physical iPhone' and raw['model'] == 'iPhone14,5'
    assert not raw.get('failureReason'), raw.get('failureReason')
    rows = raw['records']; stores = raw['stores']
    schemes = schemes or ['MultiAudit', 'Xu', 'Yu']; sizes = sizes or [10]
    summary = []
    for m in sizes:
        for name in schemes:
            audits = [r for r in rows if r['files'] == m and r['scheme'] == name and not r['warmup']]
            files = [r for r in stores if r['files'] == m and r['scheme'] == name]
            assert len(audits) == expected_repeats and len(files) == m, (name, m, len(audits), len(files))
            assert sorted(r['round'] for r in audits) == list(range(1, expected_repeats + 1))
            assert sorted(r['fileIndex'] for r in files) == list(range(m))
            for r in audits:
                assert r['verificationPerformed'] and r['accepted']
                assert (r['chunks'], r['sectors'], r['challengedChunks']) == (3907, 80, 690)
                assert r['decodeMS'] > 0 and r['verifyMS'] > 0 and r['endToEndMS'] >= r['roundTripMS']
                upload = {'Xu': 32, 'Yu': m * 64, 'MultiAudit': 32 + 4 * 690 + 32 * m * 691}[name]
                assert r['uploadBodyBytes'] == upload
                baseline = m * (96 + 690 * (64 + 12 * 32))
                if name == 'Xu': assert r['downloadBodyBytes'] == baseline
                elif name == 'Yu': assert r['downloadBodyBytes'] == baseline + m * 79 * 32
                else:
                    extra = r['downloadBodyBytes'] - (140 + m * (690 * 64 + 36))
                    assert extra >= 0 and extra % 32 == 0 and extra // 32 <= m * 690 * 12
            for f in files:
                assert (f['chunks'], f['sectors'], f['challengedChunks']) == (3907, 80, 690)
                assert f['encodedDataBytes'] == 3907 * 80 * 32
                assert f['uploadBodyBytes'] == 4 + 3907 * 80 * 32 + 3907 * 64 + 32
                assert f['storeMS'] > 0 and f['inputKind'] == 'canonical synthetic sectors'
            record = {'scheme': name, 'm': m, 'native_store_total_ms': sum(f['storeMS'] for f in files),
                      'store_upload_total_ms': sum(f['uploadMS'] for f in files),
                      'store_peak_footprint_mib': max(f['peakFootprintBytes'] for f in files) / 2**20,
                      'maximum_thermal_state': max(r['thermalState'] for r in audits)}
            for field in ['verifyMS', 'decodeMS', 'challengeMS', 'endToEndMS', 'cpuMS', 'roundTripMS', 'bridgeVerifyMS', 'downloadBodyBytes', 'uploadBodyBytes', 'peakFootprintBytes', 'serverWorkMS']:
                values = [r[field] for r in audits]
                record[field + '_median'] = statistics.median(values)
                q = statistics.quantiles(values, n=4, method='inclusive')
                record[field + '_p25'], record[field + '_p75'] = q[0], q[2]
            summary.append(record)
    configurations = len(schemes) * len(sizes)
    assert len(stores) == len(schemes)*sum(sizes) and len(rows) == configurations * (expected_repeats + raw['warmupsPerConfiguration'])
    destination.mkdir(parents=True, exist_ok=True)
    with (destination / 'summary.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summary[0])); writer.writeheader(); writer.writerows(summary)
    metadata = {'platform': raw['platform'], 'model': raw['model'], 'operating_system': raw['operatingSystem'],
                'measured_audits': configurations * expected_repeats, 'store_files': len(stores), 'm_scan': sizes, 'schemes': schemes,
                'all_measured_audits_verified': True, 'wire_sizes_match_native_formats': True,
                'phone_roles': ['owner Setup', 'Store', 'Challenge', 'optional Verify'], 'cloud_role': 'ProofGen',
                'raw_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'store_statistic': 'single complete batch per configuration; files processed sequentially',
                'audit_statistic': 'median and inclusive interquartile range; warmups retained but excluded from summary',
                'energy_measured': False, 'rows': summary}
    (destination / 'validation.json').write_text(json.dumps(metadata, indent=2) + '\n')
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('raw', type=Path)
    parser.add_argument('--out', type=Path, default=Path('experiments/results/paper/mobile'))
    parser.add_argument('--repeats', type=int, default=30)
    parser.add_argument('--files', default='10')
    parser.add_argument('--schemes', default='MultiAudit,Xu,Yu')
    arguments = parser.parse_args()
    result = summarize(arguments.raw, arguments.out, arguments.repeats, [int(m) for m in arguments.files.split(',')], arguments.schemes.split(','))
    print(json.dumps({key: value for key, value in result.items() if key != 'rows'}, indent=2))
