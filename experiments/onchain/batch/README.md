# Multi-file EVM benchmark

Run from the repository root:

```sh
EVM_BIN=/path/to/evm sh experiments/onchain/batch/run.sh
python3 experiments/onchain/batch_report.py
```

Requires Go, Python 3, Node, Solidity 0.8.25, Geth 1.17.10 `evm`, and the
`ganache` 7.9.2 and `web3` Node packages.

The benchmark tests MPA, Yu's protocol, and MultiAudit at 10, 20, 30, and 40 files.
Each file has 3,907 chunks of 80 sectors. Each audit samples 690 chunks. Five
fresh native proofs per configuration are checked in Go and executed as signed
Shanghai transactions. A separate small-parameter suite checks malformed inputs.
All schemes share the same EC/SHA-256 helpers and memory-buffer optimizations.

Results are saved to `experiments/results/paper/onchain/`. Raw receipts, calldata
hashes, source snapshots, and validation metadata support the paper's gas figure.
Lines show total receipt gas and bars show calldata gas on a single axis.
Calldata costs 4 gas per zero byte and 16 per nonzero byte. Execution excludes
calldata and the 21,000 transaction base cost. Deployment and prior registration
are excluded.

The simulator uses a 5 Ggas block limit and a 1 Ggas verification allowance.
These raised limits support cost measurement and do not establish feasibility
under a target chain's transaction limits.
