/*
 * fuzz_target.cpp — libFuzzer harness for parser.cpp.
 *
 * Passes raw fuzz bytes directly to parse(). No format wrapping so that
 * libFuzzer's mutation engine can explore the full input space.
 */

#include <cstdint>
#include <cstddef>

extern "C" int parse(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse(data, size);
    return 0;
}
