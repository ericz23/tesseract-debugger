/* Workaround for macOS SDK header order when using Homebrew LLVM 21+ with -fsanitize=fuzzer.
 * The SDK's _types.h uses types that may not be defined yet; this header forces the
 * minimal set so that SDK headers parse. Use with -include fuzz_stddef_fix.h and
 * -isystem ${LLVM_PREFIX}/include/c++/v1 (so libc++ C headers are found first). */
#ifndef TESSERACT_FUZZ_STDDEF_FIX_H
#define TESSERACT_FUZZ_STDDEF_FIX_H

#ifdef __cplusplus
extern "C" {
#endif

/* Integer types required by _types.h before arm/_types.h. */
typedef signed char           __int8_t;
typedef unsigned char         __uint8_t;
typedef short                 __int16_t;
typedef unsigned short       __uint16_t;
typedef int                   __int32_t;
typedef unsigned int          __uint32_t;
typedef long long             __int64_t;
typedef unsigned long long    __uint64_t;

#ifndef _PTRDIFF_T
#define _PTRDIFF_T
typedef __PTRDIFF_TYPE__ ptrdiff_t;
#endif

#ifndef _SIZE_T
#define _SIZE_T
typedef __SIZE_TYPE__ size_t;
#endif

#ifndef __darwin_wint_t
#ifdef __WINT_TYPE__
typedef __WINT_TYPE__ __darwin_wint_t;
#else
typedef int __darwin_wint_t;
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* TESSERACT_FUZZ_STDDEF_FIX_H */
