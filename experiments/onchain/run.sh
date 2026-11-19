#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
task_build_dir=$(mktemp -d /private/tmp/multiaudit-onchain.XXXXXX)
solc --optimize --via-ir --evm-version shanghai --combined-json abi,bin,bin-runtime \
  experiments/onchain/AuditVerifier.sol > "$task_build_dir/contract.json"
go run ./experiments/onchain -repeats 5 -out "$task_build_dir/fixtures.json"
node experiments/onchain/run.cjs "$task_build_dir/fixtures.json" "$task_build_dir/contract.json" \
  experiments/results/paper/onchain
python3 -B experiments/onchain/report.py
