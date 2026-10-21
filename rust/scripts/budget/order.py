"""does the order of candidates matter? per-file recall at fixed budgets, for several orderings.
(per-routine costs come from the run in score order; reordering changes them a little,
since lifted code is shared between routines.)"""
import os, sys, pickle, random, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim import DATA, File  # noqa
from policies import split

kind = sys.argv[2] if len(sys.argv) > 2 else "good"
files = split(pickle.load(open(DATA, "rb")), sys.argv[1] if len(sys.argv) > 1 else "all")
files = [f for f in files if f.oracle(kind)]

def recall_at(f, order, T):
    t, found = 0.0, set()
    for r in order:
        if t >= T:
            break
        t += r["seconds"]; found |= r[kind]
    return len(found) / len(f.oracle(kind))

def ideal(f):
    # greedy: most new strings per second first.
    left, seen, out = list(f.routines), set(), []
    while left:
        best = max(left, key=lambda r: len(r[kind] - seen) / max(r["seconds"], 1e-4))
        if not best[kind] - seen:
            out += sorted(left, key=lambda r: r["seconds"]); break
        out.append(best); seen |= best[kind]; left.remove(best)
    return out

orders = {
    "score (FLOSS)": lambda f: f.routines,
    "random": None,
    "fewest calls first": lambda f: sorted(f.routines, key=lambda r: (r["calls"], -r["score"])),
    "most calls first": lambda f: sorted(f.routines, key=lambda r: (-r["calls"], -r["score"])),
    "cheapest first (hindsight)": lambda f: sorted(f.routines, key=lambda r: r["seconds"]),
    "ideal (hindsight)": ideal,
}
Ts = (0.5, 1, 2, 5, 10, 30)
print(f"{len(files)} files with {kind} strings; per-file recall by decoding budget (from 0, required ones not forced first)")
print(f"{'order':<28}" + "".join(f"{T:>7}s" for T in Ts))
for name, o in orders.items():
    if o is None:
        vals = []
        for T in Ts:
            acc = []
            for seed in range(5):
                rnd = random.Random(seed)
                acc.append(statistics.mean(recall_at(f, rnd.sample(f.routines, len(f.routines)), T) for f in files))
            vals.append(statistics.mean(acc))
    else:
        cache = {f.name: o(f) for f in files}
        vals = [statistics.mean(recall_at(f, cache[f.name], T) for f in files) for T in Ts]
    print(f"{name:<28}" + "".join(f"{v:8.3f}" for v in vals))
