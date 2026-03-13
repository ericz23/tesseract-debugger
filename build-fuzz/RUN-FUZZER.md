# Running the fuzzer with separate corpus and crash directories

## Directory layout

- **`build-fuzz/fuzz_corpus`** – Corpus only. All hash-named “interesting” inputs are read from and written here.
- **`build-fuzz/fuzz_crashes`** – Artifacts only. Crash, leak, and timeout files (`crash-*`, `leak-*`, `timeout-*`, etc.) are written here.

## One-time setup

From the **repo root**:

```bash
mkdir -p build-fuzz/fuzz_corpus build-fuzz/fuzz_crashes
cp corpus/*.png build-fuzz/fuzz_corpus/
```

## Run the fuzzer

From the **repo root**:

```bash
./build-fuzz/bin/fuzzer-api -artifact_prefix=build-fuzz/fuzz_crashes/ build-fuzz/fuzz_corpus
```

- **Corpus** (hash-named files) → read from and written to `build-fuzz/fuzz_corpus/`.
- **Crashes/leaks/timeouts** → written to `build-fuzz/fuzz_crashes/` (e.g. `crash-<hash>`, `leak-<hash>`, `timeout-<hash>`).

Optional: run for a fixed time (e.g. 60 seconds):

```bash
./build-fuzz/bin/fuzzer-api -artifact_prefix=build-fuzz/fuzz_crashes/ -max_total_time=60 build-fuzz/fuzz_corpus
```
