# Running the fuzzer with separate corpus and crash directories

Two harnesses are available:

| Binary | Input interpretation | What it covers |
|---|---|---|
| `fuzzer-api` | Bitstream → synthetic 100×100 1bpp bitmap | OCR recognition path only |
| `fuzzer-api-image` | Raw bytes → `pixReadMem()` auto-detect | Leptonica decoder (PNG/JPEG/TIFF/BMP/WebP/GIF) **plus** OCR recognition path |

---

## Directory layout

- **`build-fuzz/fuzz_corpus`** – Corpus only. All hash-named "interesting" inputs are read from and written here.
- **`build-fuzz/fuzz_crashes`** – Artifacts only. Crash, leak, and timeout files (`crash-*`, `leak-*`, `timeout-*`, etc.) are written here.

---

## fuzzer-api (bitmap harness)

### One-time setup

From the **repo root**:

```bash
mkdir -p build-fuzz/fuzz_corpus build-fuzz/fuzz_crashes
cp corpus/* build-fuzz/fuzz_corpus/
```

### Run the fuzzer

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

---

## fuzzer-api-image (image-bytes harness)

This harness passes the raw fuzz input to Leptonica's `pixReadMem()`, which
auto-detects the image format from magic bytes and decodes it before handing
the resulting `PIX` to `TessBaseAPI`. This exercises the full
image-file → decoder → OCR path and is aligned with known CVE classes
(malformed JPEG, malformed TIFF, etc.).

### Build (one-time, from repo root)

```bash
./build-fuzz/clang++-fuzz-wrapper.sh \
  -O1 -g -fno-omit-frame-pointer \
  -fsanitize=address,undefined,fuzzer \
  -include "build-fuzz/fuzz_stddef_fix.h" \
  -std=c++20 -DHAVE_CONFIG_H -DCMAKE_BUILD \
  -I tesseract/include \
  -I /opt/homebrew/Cellar/leptonica/1.87.0/include/leptonica \
  -I /opt/homebrew/include \
  -I build-fuzz -I build-fuzz/include \
  tesseract/unittest/fuzzers/fuzzer-api-image.cpp \
  build-fuzz/libtesseract.a \
  -L/opt/homebrew/opt/leptonica/lib -lleptonica \
  -lcurl \
  -L/opt/homebrew/opt/llvm/lib/c++ \
  -L/opt/homebrew/opt/llvm/lib/unwind -lunwind \
  -Wl,-rpath,/opt/homebrew/opt/llvm/lib/c++ \
  -o build-fuzz/bin/fuzzer-api-image
```

### One-time corpus setup

The same `fuzz_corpus` directory is shared with `fuzzer-api`. The PNG seeds
in `corpus/` are valid starting points; libFuzzer will mutate them to probe
JPEG, TIFF, BMP, WebP, and other decoder code paths automatically.

```bash
mkdir -p build-fuzz/fuzz_corpus build-fuzz/fuzz_crashes
cp corpus/* build-fuzz/fuzz_corpus/
```

### Run the fuzzer

From the **repo root**:

```bash
./build-fuzz/bin/fuzzer-api-image -artifact_prefix=build-fuzz/fuzz_crashes/ build-fuzz/fuzz_corpus
```

- **Corpus** (hash-named files) → read from and written to `build-fuzz/fuzz_corpus/`.
- **Crashes/leaks/timeouts** → written to `build-fuzz/fuzz_crashes/` (e.g. `crash-<hash>`, `leak-<hash>`, `timeout-<hash>`).

Optional: run for a fixed time (e.g. 60 seconds):

```bash
./build-fuzz/bin/fuzzer-api-image -artifact_prefix=build-fuzz/fuzz_crashes/ -max_total_time=60 build-fuzz/fuzz_corpus
```
