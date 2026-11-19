#!/usr/bin/env bash
# mayhem/build.sh — builds the Sandboxie/common parser fuzz targets natively on Linux.
# Sandboxie itself is MSVC/Windows-only; the OS-independent parsers in Sandboxie/common
# (SimpleJSON, pattern, netfw, str_util, base64, list, rbtree) are compiled straight from
# the upstream sources with a small Windows type shim (mayhem/shim) and a malloc-backed
# POOL (mayhem/harnesses/pool_malloc.c, standing in for the VirtualAlloc-based pool.c).
# Idempotent and offline: no network, everything rebuilt into mayhem/out/.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS
cd "$SRC"

COMMON=Sandboxie/common
H=mayhem/harnesses
OUT=mayhem/out
rm -rf "$OUT"
mkdir -p "$OUT/obj-fuzz" "$OUT/obj-test"

INC=(-I mayhem/shim -I Sandboxie -I "$COMMON")
# Strict POSIX feature level keeps glibc's fd_set/timeval out of the TU (my_wsa.h defines its own).
CDEFS=(-D_POSIX_C_SOURCE=200809L -include mayhem/shim/winshim.h)
# SandboxieTools/Common/helpers.cpp gets a fake windows.h (inert Win32 stubs) instead.
WINC=(-I mayhem/shim/winapi -I SandboxieTools/Common)
CSRCS=(pattern netfw str_util base64 list rbtree)

# compile <objdir> <cflags...>: the upstream C + C++ sources and the pool stand-in.
compile() {
  local od="$1"; shift
  local s
  for s in "${CSRCS[@]}"; do
    $CC "$@" -w "${CDEFS[@]}" "${INC[@]}" -c "$COMMON/$s.c" -o "$od/$s.o"
  done
  $CC "$@" "${INC[@]}" -include mayhem/shim/winshim.h -c "$H/pool_malloc.c" -o "$od/pool_malloc.o"
  $CXX "$@" -w "${INC[@]}" -c "$COMMON/json/JSON.cpp" -o "$od/JSON.o"
  $CXX "$@" -w "${INC[@]}" -c "$COMMON/json/JSONValue.cpp" -o "$od/JSONValue.o"
  $CXX "$@" -w "${WINC[@]}" -c SandboxieTools/Common/helpers.cpp -o "$od/helpers.o"
}

# 1) the project, sanitized + instrumented for fuzzing
FFLAGS=($SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link)
compile "$OUT/obj-fuzz" "${FFLAGS[@]}"
PROJ=("$OUT"/obj-fuzz/{pattern,netfw,str_util,base64,list,rbtree,pool_malloc}.o)
JSONO=("$OUT"/obj-fuzz/{JSON,JSONValue}.o)
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/obj-fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/obj-fuzz/standalone_main.o"

# 2) harnesses: libFuzzer binary + standalone reproducer each
for t in base64 tags pattern netfw; do
  $CC "${FFLAGS[@]}" -w "${CDEFS[@]}" "${INC[@]}" -c "$H/${t}_fuzz.c" -o "$OUT/obj-fuzz/${t}_fuzz.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj-fuzz/${t}_fuzz.o" "${PROJ[@]}" \
       "$OUT/obj-fuzz/lsan_off.o" -o "$OUT/${t}_fuzz"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/obj-fuzz/${t}_fuzz.o" "${PROJ[@]}" \
       "$OUT/obj-fuzz/lsan_off.o" "$OUT/obj-fuzz/standalone_main.o" -o "$OUT/${t}_fuzz-standalone"
done
$CXX "${FFLAGS[@]}" "${INC[@]}" -c "$H/json_fuzz.cc" -o "$OUT/obj-fuzz/json_fuzz.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj-fuzz/json_fuzz.o" "${JSONO[@]}" \
     "$OUT/obj-fuzz/lsan_off.o" -o "$OUT/json_fuzz"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/obj-fuzz/json_fuzz.o" "${JSONO[@]}" \
     "$OUT/obj-fuzz/lsan_off.o" "$OUT/obj-fuzz/standalone_main.o" -o "$OUT/json_fuzz-standalone"

$CXX "${FFLAGS[@]}" "${WINC[@]}" -c "$H/getargs_fuzz.cc" -o "$OUT/obj-fuzz/getargs_fuzz.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj-fuzz/getargs_fuzz.o" "$OUT/obj-fuzz/helpers.o" \
     "$OUT/obj-fuzz/lsan_off.o" -o "$OUT/getargs_fuzz"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/obj-fuzz/getargs_fuzz.o" "$OUT/obj-fuzz/helpers.o" \
     "$OUT/obj-fuzz/lsan_off.o" "$OUT/obj-fuzz/standalone_main.o" -o "$OUT/getargs_fuzz-standalone"

# 3) known-answer self test, normal flags (no sanitizers), run by mayhem/test.sh
TFLAGS=(-O2 -g $COVERAGE_FLAGS)
compile "$OUT/obj-test" "${TFLAGS[@]}"
$CC "${TFLAGS[@]}" -w "${CDEFS[@]}" "${INC[@]}" -c mayhem/selftest/selftest_c.c -o "$OUT/obj-test/selftest_c.o"
$CXX "${TFLAGS[@]}" "${INC[@]}" "${WINC[@]}" -c mayhem/selftest/selftest.cc -o "$OUT/obj-test/selftest.o"
$CXX "${TFLAGS[@]}" "$OUT"/obj-test/*.o -o "$OUT/sbie_selftest"

echo "built: $(cd "$OUT" && ls -1 | grep -v '^obj' | tr '\n' ' ')"
