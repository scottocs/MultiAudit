"""Typeset validated owner-Store and optional-Verify measurements on iPhone."""
import base64
import csv
import hashlib
import json
import re
from pathlib import Path
from measurement_provenance import verify_sources

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / 'experiments/results/paper/mobile'
FILES = {'MultiAudit': 'multiaudit', 'Xu': 'xu', 'Yu': 'yu'}
NAMES = {'MultiAudit': r'\MultiAudit{}', 'Xu': r'MPA~\cite{XuTIFS26}', 'Yu': r'Yu et al.~\cite{YuTC25}'}



def format_algorithm_names(text):
    names = {'Setup': 'Setup', 'Store': 'Store', 'Challenge': 'Chal', 'ProofGen': 'ProofGen', 'Verify': 'Verify'}
    text = text.replace(r'\textsf{ProofGen}', r'\ProofGen{}')
    return re.sub(r'(?<![\\A-Za-z])(?:Setup|Store|Challenge|ProofGen|Verify)\b',
                  lambda match: '\\' + names[match[0]] + '{}', text)


def load_results(directory=DEFAULT):
    directory = Path(directory)
    if (directory / 'm40' / 'provenance.json').exists():
        directory = directory / 'm40'
    provenance = json.loads((directory / 'provenance.json').read_text())
    verify_sources(provenance['source_sha256'], directory / provenance['source_archive'],
                   provenance['source_archive_sha256'])
    m = provenance['configuration']['m']
    assert m in (10, 40)
    results = {}
    for scheme, stem in FILES.items():
        path = directory / (stem + '_iphone13.json')
        raw = json.loads(path.read_text())
        checked = json.loads((directory / stem / 'validation.json').read_text())
        assert checked['raw_sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert checked['all_measured_audits_verified'] and checked['measured_audits'] == 30
        assert raw['platform'] == 'physical iPhone' and raw['model'] == 'iPhone14,5'
        assert not raw.get('failureReason') and len(raw['stores']) == m
        measured = [row for row in raw['records'] if not row['warmup']]
        assert len(measured) == 30 and all(row['accepted'] and row['verificationPerformed'] for row in measured)
        assert all((row['files'], row['chunks'], row['sectors'], row['challengedChunks']) == (m, 3907, 80, 690) for row in measured)
        manifest_bytes = (directory / (stem + '_registry.json')).read_bytes()
        envelope = json.loads(manifest_bytes)
        # The owner's initial registration uses fixed-width zero root slots;
        # replacing them and the fixed-width signature preserves wire length.
        compact = lambda value: json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode()
        assert compact(envelope) == manifest_bytes
        registry_digest = hashlib.sha256(compact(envelope['body'])).hexdigest()
        assert all(row['registryDigest'] == registry_digest for row in measured)
        assert len(base64.b64decode(envelope['signature'])) == 64
        assert len(envelope['body']['roots']) == m
        for root in envelope['body']['roots']:
            assert len(base64.b64decode(root)) == 32
        envelope['body']['roots'] = [base64.b64encode(bytes(32)).decode()] * m
        envelope['signature'] = base64.b64encode(bytes(64)).decode()
        start_bytes = len(compact(envelope))
        assert start_bytes == len(manifest_bytes)
        file_upload = sum(row['uploadBodyBytes'] for row in raw['stores'])
        assert file_upload == m * 10_252_004
        stat = checked['rows'][0]
        results[scheme] = {
            'scheme': scheme, 'm': m, 'n': 3907, 's': 80, 'c': 690,
            'encoded_file_bytes': 10_001_920,
            'store_core_ms': sum(row['storeMS'] for row in raw['stores']),
            'input_construction_ms': sum(row['dataMS'] for row in raw['stores']),
            'upload_encoding_ms': sum(row['encodeMS'] for row in raw['stores']),
            'store_process_cpu_ms': sum(row['cpuMS'] for row in raw['stores']),
            'file_upload_bytes': file_upload,
            'initial_registry_bytes_fixed_width': start_bytes,
            'final_registry_bytes_observed': len(manifest_bytes),
            'store_application_upload_bytes': file_upload + start_bytes + len(manifest_bytes),
            'verify_core_median_ms': stat['verifyMS_median'],
            'verify_core_p25_ms': stat['verifyMS_p25'], 'verify_core_p75_ms': stat['verifyMS_p75'],
            'verify_client_median_ms': stat['bridgeVerifyMS_median'],
            'verify_client_p25_ms': stat['bridgeVerifyMS_p25'], 'verify_client_p75_ms': stat['bridgeVerifyMS_p75'],
            'measured_verify_rounds': 30,
            'maximum_observed_thermal_state': stat['maximum_thermal_state'],
        }
    return results


def latex_setup():
    return format_algorithm_names(r'''The Release SwiftUI client runs on a physical iPhone~13 (iOS~26.6.2, Xcode~26.1), using the shared Go code as an ARM64 library. The phone performs owner Setup and sequential Store, the cloud runs ProofGen, and optional local Verify is enabled. Store time measures native tagging and tree construction, excluding input encoding, serialization, and upload. Verify time includes proof decoding, public verification, and the Swift/Go interface. Verification reports medians of 30 fresh audits after three warmups and excludes network waiting.
''')


def latex_figure(rows):
    m = rows['MultiAudit']['m']
    assert all(row['m'] == m for row in rows.values())
    limits = (r'ymin=300,ymax=22000,ytick={300,1000,3000,10000},yticklabels={300,1000,3000,10000},' if m == 40
              else r'ymin=90,ymax=6000,ytick={100,300,1000,3000},yticklabels={100,300,1000,3000},')
    out = [r'\begin{figure}[h]', r'\centering', r'\begin{tikzpicture}',
           r'\begin{axis}[auditaxis,width=0.90\linewidth,height=0.65\linewidth,'
           r'ylabel={Time (ms)},xtick={0,1},xticklabels={Store,Verify},'
           r'xmin=-0.5,xmax=1.5,ybar=1pt,bar width=10pt,'
           r'ymode=log,log origin=infty,' + limits +
           r'legend columns=3,legend style={font=\sffamily\scriptsize,draw=none,fill=none,'
           r'at={(0.5,0.98)},anchor=north,column sep=3pt}]']
    colors = {'Xu': 'XuTIFS26', 'Yu': 'YuTC25', 'MultiAudit': 'MultiAudit'}
    for name in ['Xu', 'Yu', 'MultiAudit']:
        row = rows[name]
        color = colors[name]
        store = row['store_core_ms']
        verify = row['verify_client_median_ms']
        low = max(0, verify - row['verify_client_p25_ms'])
        high = max(0, row['verify_client_p75_ms'] - verify)
        style = ('area legend,draw=' + color + '!90!black,fill=' + color + '!75,line width=0.5pt,'
                 + r'error bars/.cd,y dir=both,y explicit,error bar style={color=black!65,line width=0.4pt},'
                 + r'error mark options={draw=black!65,rotate=90,mark size=1.5pt}')
        out += [r'\addplot+[' + style + '] coordinates {'
                + f'(0,{store:.8f}) += (0,0) -= (0,0) '
                + f'(1,{verify:.8f}) += (0,{high:.8f}) -= (0,{low:.8f})' + '};',
                r'\addlegendentry{' + NAMES[name] + '}']
    out += [r'\end{axis}', r'\end{tikzpicture}',
            r'\caption{iPhone Store and Verify times for ' + str(m) + r' 10~MB files ($s=80$, $c=690$).}',
            r'\label{fig:mobile_costs}', r'\end{figure}']
    return format_algorithm_names('\n'.join(out) + '\n')


def latex_results(directory=DEFAULT):
    rows = load_results(directory)
    f, xu, yu = rows['MultiAudit'], rows['Xu'], rows['Yu']
    xu_speedup = xu['verify_client_median_ms'] / f['verify_client_median_ms']
    yu_speedup = yu['verify_client_median_ms'] / f['verify_client_median_ms']
    text = r'''Fig.~\ref{fig:mobile_costs} compares Store and local Verify time on an iPhone~13 for ''' + str(f['m']) + r''' nominal 10~MB files. Store takes '''
    text += f"{f['store_core_ms']/1000:.3f}~s for " + r'\MultiAudit{}, compared with '
    text += f"{xu['store_core_ms']/1000:.3f}~s for " + NAMES['Xu'] + ' and '
    text += f"{yu['store_core_ms']/1000:.3f}~s for " + NAMES['Yu'] + '. '
    text += r'''The similar Store times reflect the common work of generating chunk tags and constructing complete authentication trees. CMM generation and quotient aggregation run in the cloud during audits.

Local Verify includes proof decoding, public verification, and the Swift/Go interface. '''
    text += r'\MultiAudit{} takes ' + f"{f['verify_client_median_ms']:.2f}~ms, compared with {xu['verify_client_median_ms']:.2f}~ms for MPA and {yu['verify_client_median_ms']:.2f}~ms for Yu et al." + r'~\cite{YuTC25}, giving speedups of '
    text += f"{xu_speedup:.2f}$\\times$ and {yu_speedup:.2f}$\\times$, respectively. "
    text += r'''Compact authentication reduces proof-decoding and repeated path-hashing work, while the two-witness opening combines the file claims in one verification equation. These times exclude network waiting.

'''
    return format_algorithm_names(text) + latex_figure(rows)


if __name__ == '__main__':
    rows = load_results()
    destination = DEFAULT / 'm40' if (DEFAULT / 'm40' / 'provenance.json').exists() else DEFAULT
    with (destination / 'comparison.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(next(iter(rows.values()))))
        writer.writeheader(); writer.writerows(rows.values())
    report = {'platform': 'physical iPhone 13', 'iOS': '26.6.2', 'measured_audits': 90,
              'preprocessed_files': sum(row['m'] for row in rows.values()), 'all_verified': True,
              'store_scope': f"native tag/tree computation. One complete {rows['MultiAudit']['m']}-file pass per scheme",
              'communication_scope': 'serialized application uploads including signed-registry bodies. HTTP/TCP excluded',
              'initial_registry_size_source': 'fixed-width placeholder/signature encoding. Same length as observed final body',
              'verify_scope': 'core and complete client computation, excluding network waiting',
              'rows': rows}
    (destination / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
