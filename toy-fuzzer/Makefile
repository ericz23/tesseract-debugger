# Makefile — builds all 8 fuzzer configurations for the toy parser.
#
# Configurations:
#   config-1: no sanitizers,  empty corpus     → bin/fuzzer-none
#   config-2: no sanitizers,  seeded corpus    → same binary, different run
#   config-3: ASan,           empty corpus     → bin/fuzzer-asan
#   config-4: ASan,           seeded corpus    → same binary, different run
#   config-5: UBSan,          empty corpus     → bin/fuzzer-ubsan
#   config-6: UBSan,          seeded corpus    → same binary, different run
#   config-7: ASan+UBSan,     empty corpus     → bin/fuzzer-asan-ubsan
#   config-8: ASan+UBSan,     seeded corpus    → same binary, different run
#
# Corpus selection is handled at runtime by run_experiments.sh.
# Each sanitizer config is a distinct binary (4 binaries total × 2 corpus = 8 runs).

LLVM_PREFIX ?= /opt/homebrew/opt/llvm
WRAPPER      = ../build-fuzz/clang++-fuzz-wrapper.sh
STDDEF_FIX   = ../build-fuzz/fuzz_stddef_fix.h

SRCS = target/parser.cpp harness/fuzz_target.cpp

FLAGS_COMMON = \
  -O1 -g -fno-omit-frame-pointer -std=c++20 \
  -include $(STDDEF_FIX)

# Link against Homebrew LLVM's own libc++ to match the fuzzer runtime ABI.
LDFLAGS = \
  -L$(LLVM_PREFIX)/lib/c++ \
  -L$(LLVM_PREFIX)/lib/unwind -lunwind \
  -Wl,-rpath,$(LLVM_PREFIX)/lib/c++

BIN_DIR = bin

.PHONY: all clean \
        fuzzer-none fuzzer-asan fuzzer-ubsan fuzzer-asan-ubsan

all: fuzzer-none fuzzer-asan fuzzer-ubsan fuzzer-asan-ubsan

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Config 1 & 2: fuzzer engine only, no memory/UB sanitizers.
fuzzer-none: $(BIN_DIR)
	$(WRAPPER) $(FLAGS_COMMON) \
	  -fsanitize=fuzzer \
	  $(SRCS) \
	  $(LDFLAGS) \
	  -o $(BIN_DIR)/fuzzer-none

# Config 3 & 4: AddressSanitizer.
fuzzer-asan: $(BIN_DIR)
	$(WRAPPER) $(FLAGS_COMMON) \
	  -fsanitize=address,fuzzer \
	  $(SRCS) \
	  $(LDFLAGS) \
	  -o $(BIN_DIR)/fuzzer-asan

# Config 5 & 6: UndefinedBehaviorSanitizer.
fuzzer-ubsan: $(BIN_DIR)
	$(WRAPPER) $(FLAGS_COMMON) \
	  -fsanitize=undefined,fuzzer \
	  $(SRCS) \
	  $(LDFLAGS) \
	  -o $(BIN_DIR)/fuzzer-ubsan

# Config 7 & 8: ASan + UBSan together.
fuzzer-asan-ubsan: $(BIN_DIR)
	$(WRAPPER) $(FLAGS_COMMON) \
	  -fsanitize=address,undefined,fuzzer \
	  $(SRCS) \
	  $(LDFLAGS) \
	  -o $(BIN_DIR)/fuzzer-asan-ubsan

clean:
	rm -rf $(BIN_DIR) results/
