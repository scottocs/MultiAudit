# MultiAudit

MultiAudit supports public integrity auditing of multiple outsourced files for
mobile users. It combines compact Merkle multiproofs with two-witness batched
polynomial openings. The phone performs owner preprocessing, the cloud generates
proofs, and verification runs locally or in an EVM contract.

## Contents

- `paper/MultiAudit.tex`: manuscript.
- `output/pdf/MultiAudit.pdf`: compiled paper.
- `schemes/`: MultiAudit, four comparison protocols, shared arithmetic, and tests.
- `mobile/`: iPhone client and cloud prover ([instructions](mobile/README.md)).
- `experiments/`: benchmarks, validators, and paper figure generators.
- `experiments/results/paper/`: current cloud, iPhone, and on-chain measurements.

## Validate

Requires Go and Python 3. Building the paper also requires TeX Live and latexmk.

```sh
go test ./...
go vet ./...
python3 experiments/validate_results.py
python3 experiments/mobile_report.py
python3 experiments/onchain/batch_report.py
```

## Reproduce

```sh
go run ./experiments/protocolbench
python3 experiments/publish_paper.py
latexmk -pdf -jobname=MultiAudit -interaction=nonstopmode -halt-on-error -outdir=output/pdf paper/MultiAudit.tex
```

The cloud benchmark uses complete fixtures and 30 audits per configuration. Use
native ARM64 Go on Apple silicon. Raw observations, source snapshots, and
validation metadata are retained with the results. See the [iPhone](mobile/README.md)
and [EVM](experiments/onchain/batch/README.md) instructions for device and gas tests.
