#!/bin/sh
# Assert a dynamically-linked GNU binary needs no GLIBC newer than 2.34.
# Usage: check-glibc-max.sh <binary> [max_major.max_minor]
set -eu
bin=${1:?binary}
max=${2:-2.34}
max_maj=${max%.*}
max_min=${max#*.}
if ! command -v objdump >/dev/null; then
  echo "objdump required" >&2
  exit 2
fi
vers=$(objdump -T "$bin" | sed -n 's/.*GLIBC_\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p' | sort -u)
echo "$bin GLIBC versions:"
echo "$vers" | awk '{printf "  GLIBC_%s.%s\n",$1,$2}'
echo "$vers" | awk -v maj="$max_maj" -v min="$max_min" '
  NF==2 && ($1+0>maj+0 || ($1+0==maj+0 && $2+0>min+0)) {
    printf "FAIL: GLIBC_%s.%s > %s.%s\n",$1,$2,maj,min > "/dev/stderr"
    bad=1
  }
  END { if (bad) exit 1 }
'
echo "OK: max GLIBC <= $max"
