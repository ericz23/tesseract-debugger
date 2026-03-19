#!/usr/bin/env bash
# run_experiments.sh — Execute all 8 fuzzer configurations with a 60-second
# wall-clock budget each, collect libFuzzer output logs, then print a report.
#
# Configurations:
#   cfg-1: none     + empty corpus
#   cfg-2: none     + seeded corpus
#   cfg-3: asan     + empty corpus
#   cfg-4: asan     + seeded corpus
#   cfg-5: ubsan    + empty corpus
#   cfg-6: ubsan    + seeded corpus
#   cfg-7: asan-ubsan + empty corpus
#   cfg-8: asan-ubsan + seeded corpus
#
# Run from toy-fuzzer/: ./scripts/run_experiments.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

BUDGET=60          # seconds per run
MAX_LEN=256        # cap input size to keep runs fast

CORPUS_EMPTY="corpus/empty"
CORPUS_SEEDS="corpus/seeds"

CONFIGS=(
    "cfg-1|bin/fuzzer-none|$CORPUS_EMPTY"
    "cfg-2|bin/fuzzer-none|$CORPUS_SEEDS"
    "cfg-3|bin/fuzzer-asan|$CORPUS_EMPTY"
    "cfg-4|bin/fuzzer-asan|$CORPUS_SEEDS"
    "cfg-5|bin/fuzzer-ubsan|$CORPUS_EMPTY"
    "cfg-6|bin/fuzzer-ubsan|$CORPUS_SEEDS"
    "cfg-7|bin/fuzzer-asan-ubsan|$CORPUS_EMPTY"
    "cfg-8|bin/fuzzer-asan-ubsan|$CORPUS_SEEDS"
)

mkdir -p results

echo "============================================================"
echo "  Toy Fuzzer Experiment  — $(date)"
echo "  Budget: ${BUDGET}s per run  |  max_len: ${MAX_LEN}"
echo "============================================================"
echo ""

for entry in "${CONFIGS[@]}"; do
    IFS='|' read -r cfg_name binary corpus_dir <<< "$entry"

    out_dir="results/${cfg_name}"
    corpus_runtime="${out_dir}/corpus"
    crash_dir="${out_dir}/crashes"
    log_file="${out_dir}/fuzzer.log"

    mkdir -p "$corpus_runtime" "$crash_dir"

    # Copy seeds into the runtime corpus dir (libFuzzer mutates from these).
    # For the empty condition this loop copies nothing.
    cp "$corpus_dir"/*.bin "$corpus_runtime"/ 2>/dev/null || true

    echo "--- Running ${cfg_name}: binary=$(basename $binary) corpus=$(basename $corpus_dir) ---"

    START_TS=$(date +%s)

    # Run fuzzer; libFuzzer exits on its own via -max_total_time.
    # Capture stderr (where libFuzzer logs go) to log file.
    # Non-zero exit codes are expected on crash finds.
    # Use a temp file to capture exit code past the pipe.
    set +e
    "./$binary" \
        -max_len="$MAX_LEN" \
        -max_total_time="$BUDGET" \
        -artifact_prefix="${crash_dir}/" \
        -print_final_stats=1 \
        "$corpus_runtime" \
        2>&1 | tee "$log_file"
    EXIT_CODE=${PIPESTATUS[0]}
    set -e
    # Record exit code so report.py can detect UBSan aborts (no artifact written)
    echo "FUZZER_EXIT_CODE: $EXIT_CODE" >> "$log_file"

    END_TS=$(date +%s)
    ELAPSED=$(( END_TS - START_TS ))

    echo ""
    echo "  → exit_code=$EXIT_CODE  elapsed=${ELAPSED}s  log=$log_file"
    echo ""
done

echo "============================================================"
echo "  All runs complete. Generating report..."
echo "============================================================"
echo ""

python3 scripts/report.py results/
