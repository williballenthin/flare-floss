"""compare Python FLOSS runs (decoded strings only), like FLOSS with and without floss-size-score.patch.

for each run: decoded strings that are novel (not in the file as-is, and not mostly static text),
meaningful, and text-like (see sim.py), and the share of the all-candidates oracle's text-like strings
it finds. Python FLOSS reports pieces of strings (the bytes that changed), so a string counts as found
if FLOSS reports it, or a piece of it at least 60% as long.
usage: py_compare.py RUN_DIR..."""
import os, sys, json, pickle, pathlib, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim import DATA, SAMPLES, File, Trigrams, is_static, static_grams, derived, meaningful

oracle = {f.name: f for f in pickle.load(open(DATA, "rb"))}
runs = [pathlib.Path(r) for r in sys.argv[1:]]
names = sorted(set.intersection(*({p.name[:-5] for p in r.glob("*.json")} for r in runs)) & set(oracle))
trigrams = Trigrams((SAMPLES / n).read_bytes() for n in oracle)

print(f"{len(names)} files in every run")
for run in runs:
    novel = good = words = 0
    recall = []
    times = {}
    if (run / "times.txt").exists():
        for line in open(run / "times.txt"):
            p = line.split()
            if len(p) == 3:
                times[p[0]] = float(p[2])
    for n in names:
        try:
            d = json.loads((run / f"{n}.json").read_text())
        except Exception:
            continue
        buf = (SAMPLES / n).read_bytes()
        grams = static_grams(buf)
        found = {s["string"] for s in d["strings"]["decoded_strings"]}
        nov = {s for s in found if not is_static(buf, s) and not derived(grams, s)}
        gd = {s for s in nov if meaningful(s)}
        wd = {s for s in gd if trigrams.reads_like_text(s)}
        novel += len(nov); good += len(gd); words += len(wd)
        want = oracle[n].oracle("words")
        if want:
            hit = sum(1 for s in want if s in found or any(t in s and len(t) >= 0.6 * len(s) for t in found))
            recall.append(hit / len(want))
    t = sum(times.get(n, 0) for n in names)
    print(f"{str(run):<40} novel {novel:5d}  meaningful {good:5d}  text-like {words:5d}  "
          f"recall of the oracle's text-like strings, per file {statistics.mean(recall):.3f}  time {t:7.0f}s")
