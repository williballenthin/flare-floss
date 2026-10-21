"""do any signals predict whether more strings remain? (see sim.py for the data.)

  1. dry spells: after S seconds without a new string, how often do more turn up?
  2. score cliffs: do strings stop at the biggest drop in candidate scores?
  3. the top 20: if the required candidates found nothing, do the others?
  4. file size: does the time needed grow with the number of candidates?
"""
import os, sys, pickle, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim import DATA, File  # noqa

KIND = sys.argv[1] if len(sys.argv) > 1 else "good"
SIGNAL = sys.argv[2] if len(sys.argv) > 2 else "all"
files = pickle.load(open(DATA, "rb"))


def timeline(f, kind):
    """(decoding time at the end of each routine, new strings of `kind` it found), after the required routines."""
    t, seen, out = 0.0, set(), []
    for r in f.routines:
        t += r["seconds"]
        new = r[kind] - seen
        seen |= r[kind]
        out.append((t, len(new), r["required"]))
    return out


print(f"== 1. dry spells (a dry spell: decoding time without a new {SIGNAL} string; outcome: later new {KIND} strings)")
print("   after S seconds dry   files reaching it   of those, later find more   mean strings found later")
for S in (0.25, 0.5, 1, 2, 3, 5, 10):
    reached = later = 0
    later_n = []
    for f in files:
        sig = timeline(f, SIGNAL)
        out = timeline(f, KIND)
        last = sum(r["seconds"] for r in f.routines if r["required"])   # dry spells count after the required ones
        hit = None
        for (t, n_sig, req), (_, n_out, _) in zip(sig, out):
            if req:
                continue
            if t - last >= S:
                hit = t
                break
            if n_sig:
                last = t
        if hit is None:
            continue
        reached += 1
        more = sum(n for (t, n, req) in out if t > hit)
        later += more > 0
        later_n.append(more)
    if reached:
        print(f"   {S:>6}s               {reached:5d}               {later:5d} ({later / reached:5.1%})"
              f"               {statistics.mean(later_n):6.2f}")

print(f"\n== 2. score cliffs: {KIND} strings per 100 routines, above and below each file's biggest score drop")
above = below = n_above = n_below = 0
for f in files:
    scores = [r["score"] for r in f.routines if not r["required"]]
    extra = [r for r in f.routines if not r["required"]]
    if len(extra) < 10:
        continue
    gaps = [(scores[i] - scores[i + 1], i) for i in range(len(scores) - 1)]
    _, cut = max(gaps)
    seen = set().union(*(r[KIND] for r in f.routines if r["required"]))
    for i, r in enumerate(extra):
        new = len(r[KIND] - seen); seen |= r[KIND]
        if i <= cut:
            above += new; n_above += 1
        else:
            below += new; n_below += 1
print(f"   above the cliff: {100 * above / max(n_above, 1):.2f} per 100 routines ({n_above} routines)")
print(f"   below the cliff: {100 * below / max(n_below, 1):.2f} per 100 routines ({n_below} routines)")

print(f"\n== 3. did the required candidates (top 20, tight functions) find {KIND} strings?")
for found_any in (True, False):
    group = []
    for f in files:
        req = set().union(*(r[KIND] for r in f.routines if r["required"]))
        if bool(req) != found_any:
            continue
        rest = set().union(*(r[KIND] for r in f.routines if not r["required"])) - req
        group.append(len(rest))
    if group:
        print(f"   required found {'some' if found_any else 'none'}: {len(group)} files, "
              f"{sum(1 for g in group if g)} ({sum(1 for g in group if g) / len(group):.0%}) find more later, "
              f"{sum(group)} strings later in all")

print(f"\n== 4. file size: decoding time needed for every {KIND} string, by number of candidates")
buckets = [(0, 100), (100, 300), (300, 1000), (1000, 10**9)]
for lo, hi in buckets:
    need = []
    for f in files:
        if not (lo <= f.candidates < hi) or not f.oracle(KIND):
            continue
        t, last = 0.0, 0.0
        seen = set()
        for r in f.routines:
            t += r["seconds"]
            if r[KIND] - seen:
                last = t
            seen |= r[KIND]
        need.append((last, t))
    if need:
        print(f"   {lo:>5}-{hi if hi < 10**9 else '':<5} candidates: {len(need):3d} files; time to the last string: median "
              f"{statistics.median(n for n, _ in need):5.2f}s, max {max(n for n, _ in need):5.1f}s; "
              f"as a share of all decoding: median {statistics.median(n / t for n, t in need):.0%}")
