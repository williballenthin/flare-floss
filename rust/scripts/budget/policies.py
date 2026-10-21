"""compare stopping policies for candidate decoding routines, offline (see sim.py).

usage: policies.py [train|test|all]

every policy runs the required candidates (top 20 and tight functions), then decides, before each
extra candidate, whether to keep going, using only what floss-rs knows at that point: the elapsed time,
the candidates' scores, and the strings found so far.
"""
import os, sys, pickle, hashlib, statistics, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim import DATA, File  # noqa: F401  (for unpickling)

KIND_SIGNAL = "novel"   # what counts as a new string, for the adaptive policies


def split(files, which):
    if which == "all":
        return files
    want = 0 if which == "train" else 1
    return [f for f in files if int(hashlib.sha256(f.name.encode()).hexdigest(), 16) % 2 == want]


def run(f, keep_going):
    """the number of routines run: all required ones, then extra ones while keep_going(state) says so."""
    t = 0.0
    seen = set()
    last_new_t = 0.0        # decoding time when the last new string was found
    since_new = 0           # extra routines since the last new string
    recent = []             # (t, new strings) for each extra routine
    top_score = max(r["score"] for r in f.routines)
    required_found = 0
    for i, r in enumerate(f.routines):
        if not r["required"]:
            state = dict(t=t, last_new_t=last_new_t, since_new=since_new, recent=recent,
                         score=r["score"], top_score=top_score, found=len(seen), i=i,
                         fixed=f.fixed, candidates=f.candidates, required_found=required_found)
            if not keep_going(state):
                return i
        t += r["seconds"]
        new = r[KIND_SIGNAL] - seen
        seen |= r[KIND_SIGNAL]
        if not r["required"]:
            recent.append((t, len(new)))
            since_new = 0 if new else since_new + 1
        if new:
            last_new_t = t
        if r["required"]:
            required_found = len(seen)
    return len(f.routines)


def evaluate(files, keep_going, kind):
    recalls, times, misses = [], [], 0
    got = total = 0
    for f in files:
        k = run(f, keep_going)
        found = set().union(*(r[kind] for r in f.routines[:k])) if k else set()
        oracle = f.oracle(kind)
        got += len(found); total += len(oracle)
        if oracle:
            recalls.append(len(found) / len(oracle))
            misses += len(found) < len(oracle)
        times.append(f.fixed + sum(r["seconds"] for r in f.routines[:k]))
    times.sort()
    return dict(file_recall=statistics.mean(recalls), recall=got / total, mean=statistics.mean(times),
                p95=times[int(0.95 * (len(times) - 1))], max=times[-1], misses=misses, n=len(recalls))


# --- policies -------------------------------------------------------------------------------------

def budget(T):
    return f"budget {T}s", lambda s: s["t"] < T


def patience(n, cap):
    """stop after n extra routines in a row found nothing new."""
    return f"patience {n} routines, cap {cap}s", lambda s: s["since_new"] < n and s["t"] < cap


def dry_spell(seconds, cap):
    """stop after `seconds` of decoding found nothing new."""
    return f"dry spell {seconds}s, cap {cap}s", lambda s: s["t"] - s["last_new_t"] < seconds and s["t"] < cap


def dry_ratio(beta, floor, cap):
    """stop when the time without new strings exceeds beta times the time it took to find the last one
    (and at least `floor` seconds): a dry spell judged relative to how productive decoding has been."""
    return (f"dry ratio {beta}, floor {floor}s, cap {cap}s",
            lambda s: s["t"] - s["last_new_t"] < max(floor, beta * s["last_new_t"]) and s["t"] < cap)


def rate(r, window, cap):
    """stop when the last `window` seconds of extra routines found fewer than r new strings per second."""
    def keep(s):
        if s["t"] >= cap:
            return False
        recent = [n for (t, n) in s["recent"] if t >= s["t"] - window]
        if not s["recent"] or s["recent"][0][0] > s["t"] - window:   # not enough history yet
            return True
        return sum(recent) / window >= r
    return f"rate {r}/s over {window}s, cap {cap}s", keep


def score_floor(x, cap):
    return f"score >= {x}, cap {cap}s", lambda s: s["score"] >= x and s["t"] < cap


def score_relative(a, cap):
    return f"score >= {a} x top, cap {cap}s", lambda s: s["score"] >= a * s["top_score"] and s["t"] < cap


def proportional(k, floor, cap):
    """a budget proportional to the time the rest of the analysis took."""
    return (f"{k} x other analysis, floor {floor}s, cap {cap}s",
            lambda s: s["t"] < min(cap, max(floor, k * s["fixed"])))


def per_candidate(ms, floor, cap):
    """a budget proportional to the number of candidates."""
    return (f"{ms}ms per candidate, floor {floor}s, cap {cap}s",
            lambda s: s["t"] < min(cap, max(floor, ms / 1000 * s["candidates"])))


def extend_if_found(base, more):
    """a base budget, and a longer one if the required candidates found strings."""
    return (f"budget {base}s, or {more}s if the top found strings",
            lambda s: s["t"] < (more if s["required_found"] else base))


POLICIES = (
    [budget(T) for T in (0, 0.5, 1, 2, 3, 5, 10, 20, 30, 60)]
    + [patience(n, c) for n in (10, 25, 50, 100, 200, 400) for c in (10, 30, 60)]
    + [dry_spell(d, c) for d in (0.25, 0.5, 1, 2, 3, 5) for c in (10, 30, 60)]
    + [dry_ratio(b, fl, c) for b in (0.5, 1, 2) for fl in (0.5, 1, 2) for c in (10, 30, 60)]
    + [rate(r, w, c) for r in (0.5, 1, 2) for w in (1, 2, 5) for c in (30, 60)]
    + [score_floor(x, c) for x in (0.3, 0.4, 0.5, 0.6, 0.7) for c in (30, 60)]
    + [score_relative(a, c) for a in (0.5, 0.6, 0.7, 0.8) for c in (30, 60)]
)


def pareto(rows, x="mean", y="file_recall"):
    """the rows that no other row beats on both cost and recall."""
    rows = sorted(rows, key=lambda r: (r[1][x], -r[1][y]))
    out, best = [], -1
    for r in rows:
        if r[1][y] > best:
            out.append(r); best = r[1][y]
    return out


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "train"
    files = split(pickle.load(open(DATA, "rb")), which)
    for kind in ("novel", "good"):
        rows = [(name, evaluate(files, p, kind)) for name, p in POLICIES]
        print(f"\n== {which}: {len(files)} files, recall of {kind} strings; pareto frontier (mean time vs per-file recall)")
        for name, e in pareto(rows):
            print(f"  {name:<36} per-file {e['file_recall']:.3f}  total {e['recall']:.3f}  "
                  f"mean {e['mean']:5.2f}s  p95 {e['p95']:5.1f}s  max {e['max']:5.1f}s  files missing some {e['misses']}/{e['n']}")
