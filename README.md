# MultiAudit

MultiAudit authenticates sampled tags with per-file compact Merkle multiproofs and
opens the aggregated data with two batched KZG opening witnesses (`CQ`, `CW`). A batch uses one
data SRS and distinct file-specific evaluation points. The transcript binds the
SRS, ordered file metadata, challenge, tags, and masked values; `z` is derived only
after `CQ` is fixed. Verification uses authenticated metadata independently of the
stored data. File addition and audit-set removal preserve surviving file roots.

The implementations share BN256 (go-ethereum v1.17.2), Pippenger MSM, finite-field
arithmetic, and owned scalar storage. Stored values are isolated from caller
buffers; polynomial views of owned rows are read-only. Proof encodings, challenge
domains, and verification conditions follow the paper.

## Paper and measurements

- `paper/MultiAudit.tex`: self-contained manuscript, with all figures inline.
- `output/pdf/MultiAudit.pdf`: compiled manuscript.
- `mobile/MultiAudit.xcodeproj`: iPhone client (owner Store and optional Verify).
- `experiments/results/paper/mobile/comparison.csv`: physical iPhone 13 Store/Verify comparison for ten nominal 10 MB files.
- `experiments/results/paper/runtime.csv`: Store/ProofGen/Verify statistics.
- `runtime.csv.samples.csv`: every timed observation.
- `runtime.csv.meta.json`: parameters, timing policy, backend and binary identifiers.
- `response.csv`: 30 encoded MultiAudit responses at `m=40`.
- `onchain/gas.csv` and `onchain/metadata.json`: complete single-file EVM
  verification receipts, calldata sizes, and malformed-input checks for Xu, Yu,
  and MultiAudit at `m=1`, `B=10 MB`, `s=80`, `c=690` (five fresh audits each).

The experiment fixes decimal `B=10 MB` per file, `s=80`, `c=690`, and varies
`m={10,20,30,40}`. Whole chunks give `n=3907` and 10,001,920 encoded bytes per file.
The five schemes use 20 complete fixtures and 600 measured fresh audits. Online
calls use one worker, at least three warmups and five seconds of warmup, and 30
measurements per fixture. Store is measured once; it uses sequential file paths
except for Miao's four-file worker interface. GC runs outside online timers; any
timed collection remains included. The figure reports medians and quartiles.

Yu is measured as independent file audits. Miao uses `n*s` native scalar blocks;
its keyword query matches all files. The native sampling volumes differ from the
multi-sector schemes, as stated in the paper. Communication formulas and encoded
response measurements use their declared byte conventions.

## Check and publish

```sh
go test ./...
go vet ./...
python3 experiments/validate_results.py
python3 experiments/onchain/report.py
python3 experiments/publish_paper.py
latexmk -pdf -jobname=MultiAudit -interaction=nonstopmode -halt-on-error -outdir=output/pdf paper/MultiAudit.tex
```

The publisher validates all raw statistics and embeds the three runtime panels (Store, ProofGen, Verify) and the audit-response
payload plot, all against file count. The communication plot separately compares
the Merkle-authenticated constructions on a linear MB axis.

## Rerun measurements

On Apple silicon, explicitly build native binaries if the installed Go compiler
uses amd64. Full fixtures are generated for every protocol.

```sh
GOARCH=arm64 go build -o /private/tmp/multiaudit-bench ./experiments/protocolbench
/private/tmp/multiaudit-bench -out experiments/results/paper/runtime.csv
GOARCH=arm64 go test -c -o /private/tmp/multiaudit-response.test ./schemes/multiaudit
MULTIAUDIT_RESPONSE_CSV=experiments/results/paper/response.csv /private/tmp/multiaudit-response.test -test.run '^TestResponseMeasurement$' -test.timeout 20m -test.v
```

Recorded observations retain their original labels and fingerprints. The publisher
normalizes labels using `source_rename.json` and checks the recorded source snapshots
in `measurement_sources.zip`; the archive is separate from the current implementation.

Synthetic inputs and measurement seeds support reproducibility. The security
scope is the authenticated-opening statement specified in the paper.

The single-file chain experiment uses Solidity 0.8.25 and a local Ganache 7.9.2
EVM with Shanghai pricing and a 100 Mgas block limit. Total gas includes actual
calldata and complete verification; deployment and prior challenge registration
are excluded. The caller is different from the owner. SHA-256 framing and
Fiat-Shamir domains match the native implementations. Group helpers and
equivalent arithmetic rearrangements are applied consistently. Rerun with
`sh experiments/onchain/run.sh` (requires `solc`, Go, Node, and globally installed
`ganache` and `web3`). Newer-fork limits and calldata-floor repricing are identified
separately from the measured environment.
