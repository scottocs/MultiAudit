"""Collect, validate and plot actual multi-file EVM transaction receipts."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import statistics
import zipfile

ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / 'experiments/results/paper/onchain'
SCHEMES = ['XuTIFS26', 'YuTC25', 'MultiAudit']
SCAN = [10, 20, 30, 40]
NAMES = {'XuTIFS26': r'MPA~\cite{XuTIFS26}', 'YuTC25': r'Yu et al.~\cite{YuTC25}', 'MultiAudit': r'\MultiAudit{}'}
COLORS = {'XuTIFS26': 'XuTIFS26', 'YuTC25': 'YuTC25', 'MultiAudit': 'MultiAudit'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def collect(directory=DEFAULT, smoke=None):
    rows, checks, fixtures, workers = [], [], [], []
    meta = None
    for scheme in SCHEMES:
        for m in SCAN:
            part = directory / 'parts' / f'm{m}-{scheme}'
            current = json.loads((part / 'metadata.json').read_text())
            assert current['complete'] and current['audits_per_scheme_per_m'] == 5
            if meta is None:
                meta = dict(current)
            else:
                for key in ['source_sha256', 'bytecode_sha256', 'block_gas_limit', 'transaction_gas_limit', 'n', 's', 'c', 'B_MB', 'compiler_options']:
                    assert current[key] == meta[key], key
            records = json.loads((part / 'records.json').read_text())
            assert len(records) == 5 and {r['scheme'] for r in records} == {scheme}
            assert {r['m'] for r in records} == {m}
            assert {r['repeat'] for r in records} == set(range(1, 6))
            assert len(current['negative_checks']) == 3
            rows.extend(records)
            checks.extend(current['negative_checks'])
            fixtures.extend(current['fixtures'])
            workers.append({'part': str(part.relative_to(directory)), 'scheme': scheme, 'm': m})
    assert meta is not None
    if smoke:
        small = json.loads((smoke / 'metadata.json').read_text())
        assert small['complete'] and all(meta['source_sha256'].get(name) == digest for name, digest in small['source_sha256'].items())
        assert small['bytecode_sha256'] == meta['bytecode_sha256']
        assert all(c['rejected'] for c in small['negative_checks'])
        checks.extend({**c, 'test_scope': 'Ganache same-bytecode small-parameter native batch smoke'} for c in small['negative_checks'])
        meta['smoke_evm'] = small['evm']
        meta['smoke_parameters'] = {k: small[k] for k in ['n', 's', 'c', 'm_scan']}
        meta['smoke_positive_transactions'] = len(json.loads((smoke / 'records.json').read_text()))
    meta['negative_checks'] = checks
    meta['fixtures'] = fixtures
    meta['merged_workers'] = workers
    meta['m_scan'] = SCAN
    meta['complete'] = True
    meta['successful_batch_transactions'] = len(rows)
    meta['encoded_file_bytes'] = meta['n'] * meta['s'] * 32
    meta['calldata_gas'] = '4 * zero_bytes + 16 * nonzero_bytes. Excludes the 21000 transaction base cost'
    for row in rows:
        row['calldata_gas'] = row['intrinsic_gas'] - 21000
    rows.sort(key=lambda r: (r['m'], SCHEMES.index(r['scheme']), r['repeat']))
    with (directory / 'gas.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    # Preserve the precise measured sources independently of future code changes.
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as snapshot:
        for name, expected in sorted(meta['source_sha256'].items()):
            contents = (ROOT / name).read_bytes()
            assert sha(contents) == expected, name
            snapshot.writestr(name, contents)
    (directory / 'measurement_sources.zip').write_bytes(archive.getvalue())
    meta['source_archive_sha256'] = sha(archive.getvalue())
    meta['gas_csv_sha256'] = sha((directory / 'gas.csv').read_bytes())
    (directory / 'metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
    return load_results(directory)


def load_results(directory=DEFAULT):
    meta = json.loads((directory / 'metadata.json').read_text())
    assert meta['complete'] and meta['measurement_source'] == 'local_evm_batch_transaction_receipts'
    assert meta['m_scan'] == SCAN and (meta['n'], meta['s'], meta['c'], meta['B_MB']) == (3907, 80, 690, 10)
    assert meta['native_fixtures_verified'] and meta['public_verifier_account']
    assert meta['successful_batch_transactions'] == 60
    assert all(c['rejected'] for c in meta['negative_checks'])
    formal_checks = [c for c in meta['negative_checks'] if c['m'] in SCAN]
    assert {(c['scheme'], c['m'], c['case']) for c in formal_checks} == {
        (scheme, m, case) for scheme in SCHEMES for m in SCAN
        for case in ['changed issued challenge', 'truncated proof header', 'changed first sampled tag']}
    assert len(formal_checks) == 36
    assert len(meta['fixtures']) == 12
    assert {(f['scheme'], f['m']) for f in meta['fixtures']} == {(scheme, m) for scheme in SCHEMES for m in SCAN}
    assert all(f['audits'] == 5 and len(f['sha256']) == 64 for f in meta['fixtures'])
    assert sha((directory / 'gas.csv').read_bytes()) == meta['gas_csv_sha256']
    archived = (directory / 'measurement_sources.zip').read_bytes()
    assert sha(archived) == meta['source_archive_sha256']
    with zipfile.ZipFile(io.BytesIO(archived)) as snapshot:
        for name, expected in meta['source_sha256'].items():
            assert sha(snapshot.read(name)) == expected, name
    with (directory / 'gas.csv').open() as stream:
        raw = list(csv.DictReader(stream))
    keys = {(r['scheme'], int(r['m']), int(r['repeat'])) for r in raw}
    assert len(keys) == len(raw) == 60
    assert keys == {(name, m, repeat) for name in SCHEMES for m in SCAN for repeat in range(1, 6)}
    results = {name: {} for name in SCHEMES}
    for row in raw:
        assert row['accepted'] == 'true' or row['accepted'] == 'True'
        zero, nonzero = int(row['zero_bytes']), int(row['nonzero_bytes'])
        assert zero + nonzero == int(row['calldata_bytes'])
        intrinsic = 21000 + 4 * zero + 16 * nonzero
        assert int(row['intrinsic_gas']) == intrinsic
        assert int(row['calldata_gas']) == intrinsic - 21000
        assert int(row['execution_gas']) + intrinsic == int(row['receipt_gas'])
        assert int(row['receipt_gas']) < meta['transaction_gas_limit']
        assert int(row['eip7623_projected_gas']) == 21000 + max(int(row['receipt_gas']) - 21000, 10 * (zero + 4 * nonzero))
        assert len(row['transaction_hash']) == 66
        assert (int(row['n']), int(row['s']), int(row['c'])) == (3907, 80, 690)
    assert len({r['transaction_hash'] for r in raw}) == len(raw)
    if meta.get('evm_backend', '').startswith('Geth'):
        for fixture in meta['fixtures']:
            scheme, m = fixture['scheme'], fixture['m']
            result_file = directory / 'parts' / f'm{m}-{scheme}' / 'transitions' / f'{scheme}-m{m}' / 'result.json'
            assert sha(result_file.read_bytes()) == fixture['transition_result_sha256']
            block = json.loads(result_file.read_text())
            assert not block.get('rejected') and len(block['receipts']) == 15
            assert int(block['gasUsed'], 0) <= meta['block_gas_limit']
            for index, receipt in enumerate(block['receipts']):
                assert int(receipt['status'], 0) == (1 if index < 12 else 0)
                if index >= 12:
                    assert int(receipt['gasUsed'], 0) < meta['negative_transaction_gas_limit']
            for row in [r for r in raw if r['scheme'] == scheme and int(r['m']) == m]:
                receipt = block['receipts'][2 * int(row['repeat'])]
                assert int(receipt['gasUsed'], 0) == int(row['receipt_gas'])
                assert receipt['transactionHash'] == row['transaction_hash']
    for name in SCHEMES:
        for m in SCAN:
            rows = [r for r in raw if r['scheme'] == name and int(r['m']) == m]
            result = {field: statistics.median(int(r[field]) for r in rows) for field in ['calldata_bytes', 'calldata_gas', 'response_bytes', 'execution_gas', 'receipt_gas', 'eip7623_projected_gas']}
            result['min_gas'] = min(int(r['receipt_gas']) for r in rows)
            result['max_gas'] = max(int(r['receipt_gas']) for r in rows)
            result['min_receipt_gas'] = result['min_gas']
            result['max_receipt_gas'] = result['max_gas']
            result['calldata_share_percent'] = statistics.median(100 * int(r['calldata_gas']) / int(r['receipt_gas']) for r in rows)
            for field in ['calldata_gas', 'execution_gas']:
                result['min_' + field] = min(int(r[field]) for r in rows)
                result['max_' + field] = max(int(r[field]) for r in rows)
            results[name][m] = result
    return results, meta


def latex_setup():
    return r'''The on-chain experiment uses Geth~1.17.10 to execute signed Shanghai transactions and Solidity~0.8.25 with shared BN254/SHA-256 helpers. Each configuration uses five fresh natively verified proofs, owner-registered metadata and challenges, and a public verifier account distinct from the owner. Deployment and prior registration are excluded. The local block and verification-transaction limits are raised to 5~Ggas and 1~Ggas, respectively.
'''


def latex_figure(rows):
    out = r'''\begin{figure}[t]
\centering
\begin{tikzpicture}
\begin{axis}[auditaxis,width=0.98\linewidth,height=0.76\linewidth,
 xlabel={Number of files $m$},ylabel={Gas cost (Mgas)},
 xtick={10,20,30,40},ymin=0,
 legend columns=1,
 legend style={font=\sffamily\scriptsize,draw=none,fill=none,at={(0.03,0.97)},anchor=north west}]
'''
    # Draw lighter grouped calldata bars behind the total-gas curves.
    for name, shift in zip(SCHEMES, [-8, 0, 8]):
        coordinates = ' '.join(f"({m},{row['calldata_gas']/1e6:.6f})" for m, row in rows[name].items())
        out += r'\addplot+[forget plot,ybar,mark=none,bar width=6pt,bar shift=' + str(shift) + 'pt,draw=' + COLORS[name] + '!80!black,fill=' + COLORS[name] + r'''!40] coordinates {''' + coordinates + '};\n'
        for m, row in rows[name].items():
            out += r'\node[font=\sffamily\tiny,anchor=west,rotate=90,fill=white,inner sep=0.5pt] at ([xshift=' + str(shift) + 'pt,yshift=3pt]axis cs:' + str(m) + ',' + f"{row['calldata_gas']/1e6:.6f}" + ') {' + f"{row['calldata_share_percent']:.1f}" + r'\%};' + '\n'
    for name, mark in zip(SCHEMES, ['square*', 'triangle*', '*']):
        coordinates = ' '.join(f"({m},{row['receipt_gas']/1e6:.6f}) += (0,{(row['max_gas']-row['receipt_gas'])/1e6:.6f}) -= (0,{(row['receipt_gas']-row['min_gas'])/1e6:.6f})" for m, row in rows[name].items())
        out += '\\addplot+[color=' + COLORS[name] + ',mark=' + mark + r''',line width=1pt,error bars/.cd,y dir=both,y explicit,error bar style={line width=0.4pt},error mark options={rotate=90,mark size=2pt}] coordinates {''' + coordinates + '};\n'
        out += r'\addlegendentry{' + NAMES[name] + '}\n'
    out += r'''\end{axis}
\end{tikzpicture}
\caption{EVM verification costs at $B=10$~MB per file, $s=80$, and $c=690$.}
\label{fig:onchain_cost}
\end{figure}

'''
    return out


def latex_results(directory=DEFAULT):
    rows, meta = load_results(directory)
    last = SCAN[-1]
    multi, xu = rows['MultiAudit'][last], rows['XuTIFS26'][last]
    saving = 100 * (1 - multi['receipt_gas'] / xu['receipt_gas'])
    out = latex_figure(rows)
    out += r'''Fig.~\ref{fig:onchain_cost} plots total receipt gas as lines and calldata gas as lighter bars of matching colors. Each gas value is the median of five native audits, and the line error bars span the minimum and maximum. Bar labels report the median per-audit calldata share. Total receipt gas includes execution, calldata, and the 21,000~gas transaction base cost.

Across the tested batch sizes, \MultiAudit{} remains below both baselines in total gas. The smaller calldata bars show the communication benefit of merging overlapping Merkle paths. Compact proofs also reduce authentication hashing during execution, so the gain is not limited to transaction input costs. '''
    out += f"At forty files, total gas is {saving:.1f}\\% lower than MPA's. "
    out += r'''The same elliptic-curve helpers and memory-buffer optimizations are applied to every scheme. Execution nevertheless remains the dominant component, and gas continues to grow with sampled tags and authentication work despite the two shared opening witnesses. All valid transactions succeed, and the tested malformed-input and unauthorized-update cases are rejected.

'''
    return out


def write_report(directory=DEFAULT):
    rows, meta = load_results(directory)
    summary = []
    for m in SCAN:
        for name in SCHEMES:
            summary.append({'scheme': name, 'm': m, **rows[name][m]})
    with (directory / 'summary.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summary[0]))
        writer.writeheader(); writer.writerows(summary)
    validation = {'complete': True, 'formal_transactions': len(summary)*5, 'configurations': len(summary), 'negative_checks': len(meta['negative_checks']), 'gas_csv_sha256': meta['gas_csv_sha256'], 'all_receipts_and_intrinsic_gas_valid': True, 'archived_sources_valid': True}
    (directory / 'validation.json').write_text(json.dumps(validation, indent=2) + '\n')
    print(json.dumps({'validation': validation, 'results': rows}, indent=2))


def update_paper(directory=DEFAULT):
    """Update only the chain experiment, preserving unrelated manuscript edits."""
    rows, meta = load_results(directory)
    paper = ROOT / 'paper/MultiAudit.tex'
    text = paper.read_text()
    method = 'The multi-file chain experiment uses'
    start = text.index(method)
    end = text.index('\n\n', start)
    text = text[:start] + latex_setup().rstrip() + text[end:]
    start = text.index(r'\label{subsec:onchain_costs}') + len(r'\label{subsec:onchain_costs}')
    end = text.index(r'\subsection{', start)
    text = text[:start] + '\n' + latex_results(directory).rstrip() + '\n\n' + text[end:]
    conclusion = text.index(r'\section{Conclusion}')
    start = text.index('The optimized multi-file EVM experiment', conclusion)
    end = text.index('\n', start)
    multi, xu, yu = [rows[name][40] for name in ['MultiAudit', 'XuTIFS26', 'YuTC25']]
    replacement = (f"The optimized multi-file EVM experiment reports total gas and its calldata component for batches of 10--40 files. "
                   + f"At $m=40$, \\MultiAudit{{}} consumes {multi['receipt_gas']/1e6:.2f}~Mgas in total, "
                   + f"{100*(1-multi['receipt_gas']/xu['receipt_gas']):.1f}\\% and {100*(1-multi['receipt_gas']/yu['receipt_gas']):.1f}\\% less than "
                   + NAMES['XuTIFS26'] + ' and ' + NAMES['YuTC25']
                   + ', respectively. These costs are measured under raised simulator limits and exceed ordinary single-transaction budgets.')
    text = text[:start] + replacement + text[end:]
    assert r'\label{tab:onchain_cost}' not in text
    assert text.count(r'\label{fig:onchain_cost}') == 1
    paper.write_text(text)
    publication = directory.parent / 'publication.json'
    if publication.exists():
        record = json.loads(publication.read_text())
        record['onchain_comparison'] = {
            'measurement_source': meta['measurement_source'], 'm_scan': SCAN,
            'evm': meta['evm'], 'optimization_version': meta.get('optimization_version'),
            's': meta['s'], 'B_MB': meta['B_MB'], 'c': meta['c'],
            'audits_per_scheme_per_m': 5,
            'block_gas_limit': meta['block_gas_limit'],
            'transaction_gas_limit': meta['transaction_gas_limit'],
            'results': rows}
        record['figure_panels'] = [panel for panel in record['figure_panels'] if panel not in ['Calldata gas', 'Execution gas', 'Total gas']]
        for panel in ['Total gas', 'Calldata gas']:
            if panel not in record['figure_panels']:
                record['figure_panels'].append(panel)
        publication.write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=DEFAULT)
    parser.add_argument('--collect', action='store_true')
    parser.add_argument('--smoke', type=Path)
    parser.add_argument('--update-paper', action='store_true', help='replace only the chain experiment and its conclusion sentence')
    args = parser.parse_args()
    if args.collect:
        collect(args.directory, args.smoke)
    write_report(args.directory)
    if args.update_paper:
        update_paper(args.directory)
