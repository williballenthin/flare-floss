"""fit a small linear score over a few log features, by coordinate search on one half of the files,
maximizing the mean of top-20 recall and recall at 0.5s, 1s, and 2s; then score it on the other half.
usage: fit_score.py [words|good|novel]"""
import os, sys, math
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features_study import load, top_k_recall, budget_recall, split

KIND = sys.argv[1] if len(sys.argv) > 1 else "words"
FEATURES = ["instructions", "loop_byte_mem", "tight_loops", "nzxor", "calls_out", "reach_insns", "sites_stack_ptr",
            "calls_to", "loops", "shifts", "movs", "arguments"]
data = load(KIND)
train, test = split(data, "train"), split(data, "test")
for _, rows in data:
    for r in rows:
        r["x"] = [math.log1p(r["f"].get(k, 0)) for k in FEATURES]


def scorer(w):
    return lambda f: f["_s"]


def apply(rows_data, w):
    for _, rows in rows_data:
        for r in rows:
            r["f"]["_s"] = sum(a * b for a, b in zip(w, r["x"]))


def objective(d, w):
    apply(d, w)
    s = scorer(w)
    return (top_k_recall(d, s, KIND) + sum(budget_recall(d, s, KIND, T) for T in (0.5, 1, 2))) / 4


w = [1.0] + [0.0] * (len(FEATURES) - 1)   # start from instructions alone
best = objective(train, w)
print(f"start (instructions): train objective {best:.4f}", flush=True)
for sweep in range(3):
    improved = False
    for i in range(len(FEATURES)):
        for v in (-1.0, -0.5, -0.25, 0.0, 0.25, 0.5, 1.0, 2.0):
            if i == 0 and v <= 0:
                continue
            cand = list(w); cand[i] = v
            o = objective(train, cand)
            if o > best + 1e-4:
                best, w, improved = o, cand, True
        print(f"  sweep {sweep}, after {FEATURES[i]}: {best:.4f}", flush=True) if False else None
    print(f"sweep {sweep}: train objective {best:.4f}, weights " + ", ".join(f"{k} {v:+.2f}" for k, v in zip(FEATURES, w) if v), flush=True)
    if not improved:
        break

for name, d in (("train", train), ("test", test)):
    apply(d, w)
    s = scorer(w)
    print(f"{name}: top 20 {top_k_recall(d, s, KIND):.3f}, top 50 {top_k_recall(d, s, KIND, 50):.3f}, "
          + ", ".join(f"{T}s {budget_recall(d, s, KIND, T):.3f}" for T in (0.5, 1, 2)))
