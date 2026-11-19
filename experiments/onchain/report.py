"""Validate and typeset the measured single-file EVM experiment."""
import csv
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from measurement_provenance import canonicalize, verify_sources


def load_results(directory):
    recorded = json.loads((directory / 'metadata.json').read_text())
    meta = canonicalize(recorded)
    assert meta['measurement_source'] == 'local_evm_transaction_receipts'
    assert (meta['m'], meta['B_MB'], meta['s'], meta['c'], meta['n']) == (1, 10, 80, 690, 3907)
    assert meta['native_fixtures_verified'] and meta['public_verifier_account']
    assert all(c['rejected'] for c in meta['negative_checks'])
    with (directory / 'gas.csv').open() as stream:
        raw = canonicalize(list(csv.DictReader(stream)))
    schemes = ['XuTIFS26', 'YuTC25', 'MultiAudit']
    result = {}
    for name in schemes:
        rows = [r for r in raw if r['scheme'] == name]
        assert sorted(int(r['repeat']) for r in rows) == list(range(1, meta['audits_per_scheme'] + 1))
        for row in rows:
            assert row['accepted'] == 'true'
            zero, nonzero = int(row['zero_bytes']), int(row['nonzero_bytes'])
            assert zero + nonzero == int(row['calldata_bytes'])
            intrinsic = 21000 + 4 * zero + 16 * nonzero
            execution, total = int(row['execution_gas']), int(row['receipt_gas'])
            assert intrinsic == int(row['intrinsic_gas']) and intrinsic + execution == total
            assert int(row['eip7623_projected_gas']) == 21000 + max(total - 21000, 10 * (zero + 4 * nonzero))
        result[name] = {key: statistics.median(int(r[key]) for r in rows)
                        for key in ['calldata_bytes', 'execution_gas', 'receipt_gas', 'eip7623_projected_gas']}
        result[name]['receipt_gas_min'] = min(int(r['receipt_gas']) for r in rows)
        result[name]['receipt_gas_max'] = max(int(r['receipt_gas']) for r in rows)
    assert len(raw) == len(schemes) * meta['audits_per_scheme']
    root = Path(__file__).resolve().parents[2]
    verify_sources(root, recorded['source_sha256'])
    return result, meta


def latex_setup():
    return r'''The single-file chain experiment uses Ganache~7.9.2 (Shanghai), Solidity~0.8.25 with optimization/via-IR, and a 100~Mgas local block limit. Five fresh audits per scheme share BN254/SHA-256 helpers and EIP-1108~\cite{EIP1108} prices. Bilinearity moves Xu's $\GG_2$ scalar multiplication to $\GG_1$; Yu combines $(X-z)q(X)+y$ before its SRS MSM; MultiAudit uses Equation~\eqref{eq:verify_msm}. A different account submits ABI proofs against owner-registered roots/SRS and challenge digests; indices occupy 32 bytes. Receipt gas includes calldata and execution; deployment and prior registration are excluded.
'''

def latex_results(directory):
    rows, _ = load_results(directory)
    names = {'XuTIFS26': r'Xu et al.~\cite{XuTIFS26}',
             'YuTC25': r'Yu et al.~\cite{YuTC25}', 'MultiAudit': r'\textbf{MultiAudit}'}
    out = r'''Table~\ref{tab:onchain_cost} shows that MultiAudit lowers both execution gas and calldata, reducing total gas by roughly one third relative to Xu et al.~\cite{XuTIFS26} and Yu et al.~\cite{YuTC25}. This agrees with Table~\ref{tab:communication}: CMMs avoid repeated authentication hashes, reducing both transmitted bytes and path reconstruction. Yu's pairing-free verifier still costs more overall, illustrating why the scalar/pairing counts in Table~\ref{tab:computation} must be read together with authentication and input costs. Since $m=1$, this experiment demonstrates a single-file benefit without exercising the witnesses' cross-file aggregation advantage. All 15 valid transactions succeed, and 21 tampered-input or unauthorized-update checks are rejected.

\begin{table}[t]
\centering
\caption{Measured Single-File EVM Verification ($s=80$, $B=10$~MB, $c=690$; Five Audits per Scheme)}
\label{tab:onchain_cost}
\small
\setlength{\tabcolsep}{3pt}
\begin{tabular*}{\columnwidth}{@{\extracolsep{\fill}}lrrr@{}}
\toprule
Scheme & \shortstack{Calldata\\(kB)} & \shortstack{Execution\\(Mgas)} & \shortstack{Total\\(Mgas)} \\
\midrule
'''
    for name, row in rows.items():
        values = [f"{row['calldata_bytes']/1000:.2f}",
                  f"{row['execution_gas']/1e6:.2f}", f"{row['receipt_gas']/1e6:.2f}"]
        if name == 'MultiAudit':
            values = [r'\textbf{' + value + '}' for value in values]
        out += names[name] + ' & ' + ' & '.join(values) + r' \\' + '\n'
    out += r'''\bottomrule
\end{tabular*}
\par\smallskip
\footnotesize kB $=10^3$ bytes; Mgas $=10^6$ gas. Execution excludes transaction intrinsic gas; total includes it.
\end{table}
'''
    out += r'''Applying the EIP-7623~\cite{EIP7623} calldata floor to the recorded inputs while holding measured execution fixed leaves these totals unchanged; this is a repricing projection, not a newer-fork measurement. Only MultiAudit's measured totals fit the $2^{24}$ transaction cap of EIP-7825~\cite{EIP7825}, so target-chain limits remain relevant even for a single file.
'''
    return out


if __name__ == '__main__':
    results, metadata = load_results(Path(__file__).resolve().parents[1] / 'results/paper/onchain')
    print(json.dumps({'parameters': {'m': 1, 's': 80, 'B_MB': 10, 'c': 690},
                      'measurements_valid': True, 'results': results}, indent=2))
