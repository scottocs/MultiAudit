#!/bin/sh
# Background command-line workflow; no browser, wallet or GUI required.
set -eu
cd "$(dirname "$0")/../../.."
task_build_dir=$(mktemp -d /private/tmp/multiaudit-onchain-batch.XXXXXX)
task_output=${1:-experiments/results/paper/onchain}
task_evm=$(command -v "${EVM_BIN:-evm}")
export GOCACHE=${GOCACHE:-/private/tmp/multiaudit-go-cache}
case "$(uname -m)" in
  arm64) export GOARCH=arm64 ;;
esac
solc --optimize --via-ir --evm-version shanghai --combined-json abi,bin,bin-runtime \
  experiments/onchain/batch/AuditBatchVerifier.sol > "$task_build_dir/contract.json"
go build -o "$task_build_dir/fixtures" ./experiments/onchain/batch
"$task_build_dir/fixtures" -out-dir "$task_build_dir/smoke" -m 2 -n 64 -s 8 -c 20 -repeats 1
node experiments/onchain/batch/run.cjs "$task_build_dir/smoke" "$task_build_dir/contract.json" \
  "$task_output/smoke" --negative
"$task_build_dir/fixtures" -out-dir "$task_build_dir/formal" -m 10,20,30,40 -n 3907 -s 80 -c 690 -repeats 5
python3 -u experiments/onchain/batch/run_grid.py "$task_build_dir/formal" "$task_build_dir/contract.json" "$task_output" --workers 4 --evm "$task_evm" --smoke-metadata "$task_output/smoke/metadata.json"
python3 -B experiments/onchain/batch_report.py --directory "$task_output" --collect --smoke "$task_output/smoke"
