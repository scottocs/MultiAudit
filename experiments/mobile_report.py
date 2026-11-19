"""Typeset validated owner-Store and optional-Verify measurements on iPhone."""
import base64
import csv
import hashlib
import json
from pathlib import Path
from measurement_provenance import verify_sources

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / 'experiments/results/paper/mobile'
FILES = {'MultiAudit': 'multiaudit', 'Xu': 'xu', 'Yu': 'yu'}
NAMES = {'MultiAudit': r'\textbf{MultiAudit}', 'Xu': r'Xu et al.~\cite{XuTIFS26}', 'Yu': r'Yu et al.~\cite{YuTC25}'}


def load_results(directory=DEFAULT):
    provenance = json.loads((directory / 'provenance.json').read_text())
    verify_sources(ROOT, provenance['source_sha256'])
    results = {}
    for scheme, stem in FILES.items():
        path = directory / (stem + '_iphone13.json')
        raw = json.loads(path.read_text())
        checked = json.loads((directory / stem / 'validation.json').read_text())
        assert checked['raw_sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert checked['all_measured_audits_verified'] and checked['measured_audits'] == 30
        assert raw['platform'] == 'physical iPhone' and raw['model'] == 'iPhone14,5'
        assert not raw.get('failureReason') and len(raw['stores']) == 10
        measured = [row for row in raw['records'] if not row['warmup']]
        assert len(measured) == 30 and all(row['accepted'] and row['verificationPerformed'] for row in measured)
        assert all((row['files'], row['chunks'], row['sectors'], row['challengedChunks']) == (10, 3907, 80, 690) for row in measured)
        manifest_bytes = (directory / (stem + '_registry.json')).read_bytes()
        envelope = json.loads(manifest_bytes)
        # The owner's initial registration uses fixed-width zero root slots;
        # replacing them and the fixed-width signature preserves wire length.
        compact = lambda value: json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode()
        assert compact(envelope) == manifest_bytes
        registry_digest = hashlib.sha256(compact(envelope['body'])).hexdigest()
        assert all(row['registryDigest'] == registry_digest for row in measured)
        assert len(base64.b64decode(envelope['signature'])) == 64
        for root in envelope['body']['roots']:
            assert len(base64.b64decode(root)) == 32
        envelope['body']['roots'] = [base64.b64encode(bytes(32)).decode()] * 10
        envelope['signature'] = base64.b64encode(bytes(64)).decode()
        start_bytes = len(compact(envelope))
        assert start_bytes == len(manifest_bytes)
        file_upload = sum(row['uploadBodyBytes'] for row in raw['stores'])
        assert file_upload == 102_520_040
        stat = checked['rows'][0]
        results[scheme] = {
            'scheme': scheme, 'm': 10, 'n': 3907, 's': 80, 'c': 690,
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
    return r'''The Release SwiftUI client runs on a physical iPhone~13 (iOS~26.6.2; Xcode~26.1), using the shared Go code as an ARM64 library. For $m=10$, the phone performs fresh owner setup and sequential Store; the host runs ProofGen with public parameters. Local Verify is optional and enabled in these tests. Store sums native per-file preprocessing, excluding setup, input construction, encoding, and network waiting. Upload bytes include files and signed-registry bodies (fixed-width root slots), excluding HTTP/TCP headers. Thirty fresh audits follow three warmups. Core Verify excludes decoding; client Verify includes decoding and the common Swift/Go interface. Both exclude network waiting.
'''

def latex_results(directory=DEFAULT):
    rows = load_results(directory)
    f = rows['MultiAudit']
    core_savings = {name: 100 * (1 - f['verify_core_median_ms'] / rows[name]['verify_core_median_ms']) for name in ['Xu', 'Yu']}
    client_savings = {name: 100 * (1 - f['verify_client_median_ms'] / rows[name]['verify_client_median_ms']) for name in ['Xu', 'Yu']}
    text = r'''Table~\ref{tab:mobile_costs} complements Tables~\ref{tab:computation} and~\ref{tab:communication}. For ten files, each scheme generates $mn=39{,}070$ tags and constructs complete per-file authentication trees during Store. The measured file uploads contain the same encoded sectors and tags, totaling 102,520,040 bytes per scheme; signed-registry bodies bring each application upload to approximately 102.54~MB. This common preprocessing explains the similar Store times. The cloud generates CMMs for the sampled set $J$ during ProofGen, reducing subsequent audit responses and authentication work. The two aggregate witnesses likewise target cloud ProofGen, leaving the initial tag and data upload unchanged.

'''
    text += (f"MultiAudit reduces native Verify time by {core_savings['Xu']:.1f}\\% relative to {NAMES['Xu']} and {core_savings['Yu']:.1f}\\% relative to {NAMES['Yu']}. "
             f"Including decoding and the shared language interface, complete local verification takes {f['verify_client_median_ms']:.2f}~ms, reductions of {client_savings['Xu']:.1f}\\% and {client_savings['Yu']:.1f}\\%, respectively. ")
    text += r'''Relative to Xu, reduced authentication hashing helps despite comparable leading tag-MSM terms. Against Yu, batching also avoids repeated per-file opening checks. The larger client difference additionally reflects processing smaller audit responses.

\begin{table}[t]
\centering
\caption{Measured iPhone~13 Costs for Ten 10~MB Files ($s=80$, $c=690$)}
\label{tab:mobile_costs}
\small
\setlength{\tabcolsep}{2pt}
\begin{tabular*}{\columnwidth}{@{\extracolsep{\fill}}ccccc@{}}
\toprule
Scheme & \shortstack{Store\\(s)} & \shortstack{Store upload\\(MB)} & \shortstack{Core Verify\\(ms)} & \shortstack{Client Verify\\(ms)} \\
\midrule
'''
    for name in ['Xu', 'Yu', 'MultiAudit']:
        row = rows[name]
        core = f"{row['verify_core_median_ms']:.2f}"
        client = f"{row['verify_client_median_ms']:.2f}"
        if name == 'MultiAudit':
            core = r'\textbf{' + core + '}'
            client = r'\textbf{' + client + '}'
        text += NAMES[name] + f" & {row['store_core_ms']/1000:.3f} & {row['store_application_upload_bytes']/1e6:.2f} & " + core + ' & ' + client + r' \\' + '\n'
    text += r'''\bottomrule
\end{tabular*}
\par\smallskip
\footnotesize Store is one complete pass; Verify columns are medians of 30 audits. Core excludes decoding; client includes decoding and the common language interface. Uploads include signed-registry bodies; MB $=10^6$ bytes.
\end{table}
'''
    return text


def abstract_sentence(directory=DEFAULT):
    rows = load_results(directory); f = rows['MultiAudit']
    x = 100 * (1 - f['verify_client_median_ms'] / rows['Xu']['verify_client_median_ms'])
    y = 100 * (1 - f['verify_client_median_ms'] / rows['Yu']['verify_client_median_ms'])
    return (f" A physical iPhone~13 client performs owner Store and optional verification; complete local verification, including decoding and interface overhead, is {x:.1f}\\% and {y:.1f}\\% faster than {NAMES['Xu']} and {NAMES['Yu']} for ten files.")


if __name__ == '__main__':
    rows = load_results()
    with (DEFAULT / 'comparison.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(next(iter(rows.values()))))
        writer.writeheader(); writer.writerows(rows.values())
    report = {'platform': 'physical iPhone 13', 'iOS': '26.6.2', 'measured_audits': 90,
              'preprocessed_files': 30, 'all_verified': True,
              'store_scope': 'native tag/tree preprocessing; one complete ten-file pass per scheme',
              'communication_scope': 'serialized application uploads including signed-registry bodies; HTTP/TCP excluded',
              'initial_registry_size_source': 'fixed-width placeholder/signature encoding; same length as observed final body',
              'verify_scope': 'core and complete client computation, excluding network waiting',
              'rows': rows}
    (DEFAULT / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
