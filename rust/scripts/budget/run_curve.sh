#!/bin/bash
# emulate every candidate decoding routine of each file (up to BUDGET seconds), recording what each costs and finds.
# usage: run_curve.sh FLOSS_RS SAMPLES_DIR FILE_LIST OUTDIR [BUDGET]
# FILE_LIST names the samples, one per line, relative to SAMPLES_DIR. three files run at a time, one thread each.
FLOSS_RS=$(realpath "$1"); SAMPLES=$2; LIST=$(realpath "$3"); OUT=$(realpath -m "$4"); BUDGET=${5:-60}
mkdir -p "$OUT"
cp "$FLOSS_RS" "$OUT/floss-rs"   # a copy, so rebuilding during the run doesn't mix versions.
cd "$SAMPLES" || exit 1
: > "$OUT/times.txt"
one() {
  s=$(date +%s.%N)
  timeout 900 "$OUT/floss-rs" -j --no static --threads 1 --time-budget "$BUDGET" -- "$1" > "$OUT/$1.json" 2> "$OUT/$1.err"
  rc=$?
  echo "$1 $rc $(echo "$(date +%s.%N) - $s" | bc)" >> "$OUT/times.txt"
}
export -f one; export OUT BUDGET
xargs -P 3 -I{} bash -c 'one {}' < "$LIST"
echo DONE >> "$OUT/times.txt"
