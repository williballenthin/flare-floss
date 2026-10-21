"""a focused comparison: fixed budgets vs. "stop after a dry spell", for several definitions of a new string."""
import os, sys, pickle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim import DATA, File  # noqa
import policies as bp

which = sys.argv[1] if len(sys.argv) > 1 else "all"
files = bp.split(pickle.load(open(DATA, "rb")), which)
print(f"{which}: {len(files)} files")
fmt = "  {:<40} good {:.3f} ({:2d} files miss)  novel {:.3f}  mean {:5.2f}s  p95 {:5.1f}s  max {:5.1f}s"
def show(name, p):
    g = bp.evaluate(files, p, "good"); n = bp.evaluate(files, p, "novel")
    print(fmt.format(name, g["file_recall"], g["misses"], n["file_recall"], g["mean"], g["p95"], g["max"]))
for T in (1, 2, 3, 5, 10, 20):
    show(*bp.budget(T))
print("-- budgets that scale with the file")
for k in (1, 2, 3, 5):
    for fl in (1, 2):
        show(*bp.proportional(k, fl, 30))
for ms in (5, 10, 20, 40):
    show(*bp.per_candidate(ms, 1, 30))
for base, more in ((1, 5), (2, 10), (2, 20), (5, 20)):
    show(*bp.extend_if_found(base, more))
for signal in ("all",):
    bp.KIND_SIGNAL = signal
    print(f"-- dry spell, where 'new' means a new {signal} string")
    for d in (0.5, 1, 2, 3):
        for cap in (10, 30):
            show(*bp.dry_spell(d, cap))
