#!/bin/bash
# Wrapper so that libc++ include path is searched first when building with -fsanitize=fuzzer.
# Usage: CMAKE_CXX_COMPILER="$PWD/clang++-fuzz-wrapper.sh" cmake ...
LLVM_PREFIX="${LLVM_PREFIX:-/opt/homebrew/opt/llvm}"
# Use -nostdinc so we control order: libc++ first, then resource dir (stdarg.h etc), then SDK.
RESOURCE_DIR="$("$LLVM_PREFIX/bin/clang++" -print-resource-dir)"
SDK_INCLUDE="${SDKROOT:-/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk}/usr/include"
exec "$LLVM_PREFIX/bin/clang++" -nostdinc \
  -isystem "$LLVM_PREFIX/include/c++/v1" \
  -isystem "$RESOURCE_DIR/include" \
  -isystem "$SDK_INCLUDE" \
  "$@"
