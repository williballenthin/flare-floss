"""the numbers for the write-up: budget curves (1 thread, and simulated with several threads),
by file size, and the adaptive rules, from the all-candidates run. writes budget_final.json too."""
import os, sys, pickle, statistics, json, heapq
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim import DATA, File  # noqa
import policies as bp

files = pickle.load(open(DATA, "rb"))
HELPERS_AFTER, SETUP = 0.3, 0.3


def schedule(f, T, threads):
    """simulate decoding with `threads` workers taking candidates in order; returns (routines run, wall time)."""
    workers = [0.0]                                    # when each worker is next free
    started_helpers = False
    ran = []
    clock = 0.0
    heap = [(0.0, 0)]
    for i, r in enumerate(f.routines):
        free, w = heapq.heappop(heap)
        clock = free
        if not r["required"] and clock >= T:
            heapq.heappush(heap, (free, w))
            break
        heapq.heappush(heap, (free + r["seconds"], w))
        ran.append(i)
        if not started_helpers and threads > 1 and free + r["seconds"] >= HELPERS_AFTER:
            started_helpers = True
            start = free + r["seconds"] + SETUP
            for k in range(1, threads):
                heapq.heappush(heap, (start, k))
    end = max(t for t, _ in heap) if ran else 0.0
    return ran, end


def curve(T, threads, subset=None, kind="good"):
    fs = subset if subset is not None else files
    recalls, times = [], []
    got = total = 0
    for f in fs:
        ran, wall = schedule(f, T, threads)
        found = set().union(*(f.routines[i][kind] for i in ran)) if ran else set()
        oracle = f.oracle(kind)
        if oracle:
            recalls.append(len(found) / len(oracle))
        got += len(found); total += len(oracle)
        times.append(f.fixed + wall)
    times.sort()
    return dict(T=T, threads=threads, kind=kind, file_recall=statistics.mean(recalls), recall=got / max(total, 1),
                mean=statistics.mean(times), median=times[len(times) // 2],
                p95=times[int(0.95 * (len(times) - 1))], max=times[-1], over10=sum(t > 10 for t in times))


Ts = [0, 0.25, 0.5, 1, 2, 3, 5, 7.5, 10, 15, 20, 30, 60]
out = {"curves": [], "by_size": [], "policies": []}
for threads in (1, 4):
    print(f"\n== {threads} thread(s): per-file recall (good / novel), whole-file time")
    for T in Ts:
        g, n = curve(T, threads, kind="good"), curve(T, threads, kind="novel")
        out["curves"].append(g); out["curves"].append(n)
        print(f"  budget {T:>5}s  good {g['file_recall']:.3f}  novel {n['file_recall']:.3f}  mean {g['mean']:5.2f}s  "
              f"median {g['median']:4.2f}s  p95 {g['p95']:5.1f}s  max {g['max']:5.1f}s  files over 10s {g['over10']}")

print("\n== by number of candidates: per-file recall of good strings")
for lo, hi in [(0, 300), (300, 1000), (1000, 10**9)]:
    fs = [f for f in files if lo <= f.candidates < hi]
    row = {"lo": lo, "hi": hi, "files": len(fs)}
    for threads in (1, 4):
        row[threads] = {T: curve(T, threads, fs)["file_recall"] for T in (1, 2, 5, 10, 20)}
    out["by_size"].append(row)
    print(f"  {lo}-{hi if hi < 10**9 else '':<6} {len(fs):3d} files  1 thread: " + " ".join(f"{T}s {v:.3f}" for T, v in row[1].items())
          + "   4 threads: " + " ".join(f"{T}s {v:.3f}" for T, v in row[4].items()))

print("\n== adaptive rules (1 thread)")
bp.KIND_SIGNAL = "all"
for name, p in [bp.budget(5), bp.budget(10), bp.dry_spell(1, 30), bp.dry_spell(2, 30), bp.dry_spell(3, 30),
                bp.extend_if_found(2, 20), bp.extend_if_found(5, 20), bp.proportional(3, 1, 30), bp.per_candidate(10, 1, 30),
                bp.score_floor(0.4, 60), bp.patience(100, 30)]:
    e = bp.evaluate(files, p, "good")
    out["policies"].append(dict(name=name, **e))
    print(f"  {name:<44} good {e['file_recall']:.3f}  mean {e['mean']:5.2f}s  p95 {e['p95']:5.1f}s  max {e['max']:5.1f}s")

json.dump(out, open("budget_final.json", "w"), indent=1)
