"""score real runs against the all-candidates oracle (curve60c): per-file recall and wall time.
usage: score.py RUN_DIR..."""
import os, sys, pickle, pathlib, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim import DATA, SAMPLES, File, Trigrams

oracle = {f.name: f for f in pickle.load(open(DATA, "rb"))}
# the same model of text that the oracle was scored with (see sim.load).
trigrams = Trigrams((SAMPLES / name).read_bytes() for name in oracle)
for run in sys.argv[1:]:
    times = {}
    for line in open(pathlib.Path(run) / "times.txt"):
        p = line.split()
        if len(p) == 3:
            times[p[0]] = float(p[2])
    rec = {"words": [], "good": [], "novel": []}
    for name, o in oracle.items():
        try:
            f = File(pathlib.Path(run) / f"{name}.json", trigrams)
        except Exception:
            continue
        for kind in rec:
            want = o.oracle(kind)
            if want:
                got = set().union(*(r[kind] for r in f.routines)) if f.routines else set()
                rec[kind].append(len(got & want) / len(want))
    t = sorted(times[n] for n in oracle if n in times)
    print(f"{run}: per-file recall words {statistics.mean(rec['words']):.3f} good {statistics.mean(rec['good']):.3f} novel {statistics.mean(rec['novel']):.3f}; "
          f"wall mean {statistics.mean(t):.2f}s median {t[len(t)//2]:.2f}s p95 {t[int(.95*(len(t)-1))]:.1f}s max {t[-1]:.1f}s")
