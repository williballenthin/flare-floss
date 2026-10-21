"""hand-written candidate scores, each changing one thing about FLOSS's, scored like score_study.py.
usage: hand_scores.py [words|good|novel] [all|train|test]"""
import os, sys, math
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features_study import load, top_k_recall, budget_recall, split

KIND = sys.argv[1] if len(sys.argv) > 1 else "words"
WHICH = sys.argv[2] if len(sys.argv) > 2 else "all"
data = load(KIND)
if WHICH != "all":
    data = split(data, WHICH)
for _, rows in data:
    m = max((r["f"].get("calls_to", 0) for r in rows), default=0)
    for r in rows:
        r["f"]["_max_calls"] = m

LOW, MEDIUM, HIGH, SEVERE = 0.25, 0.5, 0.75, 1.0


def block_score(n):
    return 0.1 if n > 30 else 1.0 if 3 <= n <= 10 else 0.4


def floss(f, per_type=False, calls="linear", crypto=False, size=False, extra=False):
    """FLOSS's weighted average, with options:
      per_type: each kind of instruction feature counts once (scored by how many there are, up to 1),
                rather than once per instruction;
      calls:    "linear" (count / max, like FLOSS) or "log" (log count / log max);
      crypto:   functions with dozens of xors in straight-line code are hashing or crypto, not decoding;
      size:     instruction count scores up with size, rather than a step at 10;
      extra:    add features about loops over bytes, and calls to functions with loops."""
    feats = []  # (weight, score)
    feats.append((LOW, block_score(f.get("blocks", 0))))
    n = f.get("instructions", 0)
    feats.append((LOW, min(1.0, math.log1p(n) / math.log1p(200)) if size else (0.8 if n > 10 else 0.1)))
    a = f.get("arguments", 0)
    feats.append((LOW, 1.0 if 1 <= a <= 4 else 0.5 if 5 <= a <= 6 else 0.0))
    c, m = f.get("calls_to", 0), max(f.get("_max_calls", 1), 1)
    feats.append((MEDIUM, (math.log1p(c) / math.log1p(m)) if calls == "log" else c / m))
    for k, w in (("loops", MEDIUM), ("tight_loops", HIGH)):
        if f.get(k, 0):
            feats += [(w, 1.0)] if per_type else [(w, 1.0)] * f[k]
    for k, w in (("nzxor", HIGH), ("shifts", HIGH), ("movs", MEDIUM)):
        cnt = f.get(k, 0)
        if per_type:
            feats.append((w, min(1.0, cnt / 3)))
        else:
            feats += [(w, 1.0)] * cnt
    if f.get("tight_function"):
        feats.append((SEVERE, 0.0))
    if f.get("nzxor_tight_loop"):
        feats += [(SEVERE, 1.0)] * (1 if per_type else f["nzxor_tight_loop"])
    if f.get("nzxor_loop"):
        feats.append((SEVERE, 1.0))
    if extra:
        feats.append((HIGH, min(1.0, f.get("loop_byte_mem", 0) / 2)))
        feats.append((MEDIUM, min(1.0, f.get("calls_to_loopy", 0) / 3)))
    score = sum(w * s for w, s in feats) / sum(w for w, _ in feats)
    if crypto and f.get("nzxor", 0) > 30 and f.get("loops", 0) == 0:
        score *= 0.5
    return score


SCORES = [
    ("FLOSS score (as computed)", lambda f: f["score"]),
    ("FLOSS, recomputed", lambda f: floss(f)),
    ("+ per-type", lambda f: floss(f, per_type=True)),
    ("+ per-type, log calls", lambda f: floss(f, per_type=True, calls="log")),
    ("+ per-type, log calls, size", lambda f: floss(f, per_type=True, calls="log", size=True)),
    ("+ per-type, log calls, size, crypto", lambda f: floss(f, per_type=True, calls="log", size=True, crypto=True)),
    ("+ all of the above, extra features", lambda f: floss(f, per_type=True, calls="log", size=True, crypto=True, extra=True)),
    ("instructions", lambda f: f.get("instructions", 0)),
]

if __name__ == "__main__":
    print(f"{len(data)} files ({WHICH}); share of each file's {KIND} strings found")
    print(f"{'score':<44} {'top 20':>7} {'top 50':>7} " + " ".join(f"{T:>6}s" for T in (0.25, 0.5, 1, 2)))
    for name, s in SCORES:
        print(f"{name:<44} {top_k_recall(data, s, KIND):7.3f} {top_k_recall(data, s, KIND, 50):7.3f} "
              + " ".join(f"{budget_recall(data, s, KIND, T):7.3f}" for T in (0.25, 0.5, 1, 2)), flush=True)
