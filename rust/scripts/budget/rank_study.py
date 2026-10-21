"""which candidate features predict that a decoding routine yields strings, and what it costs?
trains on one half of the files, evaluates on the other. run with the venv that has scikit-learn."""
import os, sys, pickle, math, statistics, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim import DATA, File  # noqa
from policies import split
import numpy as np
from sklearn.linear_model import LogisticRegression, LinearRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import roc_auc_score, average_precision_score

KIND = sys.argv[1] if len(sys.argv) > 1 else "good"
FEATURES = ["blocks", "instructions", "arguments", "calls_to", "loops", "tight_loops", "tight_function",
            "nzxor", "shifts", "movs", "nzxor_tight_loop", "nzxor_loop"]

all_files = pickle.load(open(DATA, "rb"))
train, test = split(all_files, "train"), split(all_files, "test")


def rows(files):
    X, y, cost, groups = [], [], [], []
    for fi, f in enumerate(files):
        max_calls = max((r["features"].get("calls_to", 0) for r in f.routines), default=1) or 1
        for r in f.routines:
            ft = r["features"]
            x = [math.log1p(ft.get(k, 0)) for k in FEATURES]
            x += [ft.get("calls_to", 0) / max_calls, r["score"]]
            X.append(x); y.append(1 if r[KIND] else 0); cost.append(math.log(max(r["seconds"], 1e-5))); groups.append(fi)
    return np.array(X), np.array(y), np.array(cost), groups


Xtr, ytr, ctr, _ = rows(train)
Xte, yte, cte, _ = rows(test)
names = [f"log {k}" for k in FEATURES] + ["calls_to / max", "FLOSS score"]
print(f"routines: train {len(ytr)} ({ytr.sum()} yield {KIND}), test {len(yte)} ({yte.sum()} yield)")

print("\n-- predicting 'yields strings' (test split) --")
print(f"  FLOSS score alone          AUC {roc_auc_score(yte, Xte[:, -1]):.3f}  AP {average_precision_score(yte, Xte[:, -1]):.3f}")
for i, n in enumerate(names[:-1]):
    a = roc_auc_score(yte, Xte[:, i])
    print(f"  {n:<26} AUC {a:.3f}")
lr = LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced").fit(Xtr, ytr)
p_lr = lr.predict_proba(Xte)[:, 1]
print(f"  logistic regression        AUC {roc_auc_score(yte, p_lr):.3f}  AP {average_precision_score(yte, p_lr):.3f}")
for n, c in sorted(zip(names, lr.coef_[0]), key=lambda t: -abs(t[1])):
    print(f"      {n:<24} {c:+.2f}")
gb = GradientBoostingClassifier(random_state=0).fit(Xtr, ytr)
p_gb = gb.predict_proba(Xte)[:, 1]
print(f"  gradient boosting          AUC {roc_auc_score(yte, p_gb):.3f}  AP {average_precision_score(yte, p_gb):.3f}")

print("\n-- predicting log(seconds) --")
reg = LinearRegression().fit(Xtr[:, :-1], ctr)
pred_cost = reg.predict(Xte[:, :-1])
ss = ((cte - pred_cost) ** 2).sum(); st = ((cte - cte.mean()) ** 2).sum()
print(f"  linear R^2 on test {1 - ss / st:.3f}")
for n, c in sorted(zip(names[:-1], reg.coef_), key=lambda t: -abs(t[1]))[:6]:
    print(f"      {n:<24} {c:+.2f}")

# replay budgets on the test files in several orders.
def ordered(f, key):
    req = [r for r in f.routines if r["required"]]
    return sorted(f.routines, key=key)


def per_file_recall(files, order_of, T, kind=KIND):
    out = []
    for f in files:
        oracle = f.oracle(kind)
        if not oracle:
            continue
        t, found = 0.0, set()
        for r in order_of(f):
            if t >= T:
                break
            t += r["seconds"]; found |= r[kind]
        out.append(len(found) / len(oracle))
    return statistics.mean(out)


def featurize(f):
    max_calls = max((r["features"].get("calls_to", 0) for r in f.routines), default=1) or 1
    X = [[math.log1p(r["features"].get(k, 0)) for k in FEATURES] + [r["features"].get("calls_to", 0) / max_calls, r["score"]]
         for r in f.routines]
    return np.array(X)


order_lr, order_gb, order_lr_cost = {}, {}, {}
for f in test:
    X = featurize(f)
    plr = lr.predict_proba(X)[:, 1]; pgb = gb.predict_proba(X)[:, 1]
    c = np.exp(reg.predict(X[:, :-1]))
    order_lr[f.name] = [r for _, r in sorted(zip(-plr, f.routines), key=lambda t: t[0])]
    order_gb[f.name] = [r for _, r in sorted(zip(-pgb, f.routines), key=lambda t: t[0])]
    order_lr_cost[f.name] = [r for _, r in sorted(zip(-plr / c, f.routines), key=lambda t: t[0])]

orders = {
    "FLOSS score": lambda f: f.routines,
    "logistic": lambda f: order_lr[f.name],
    "gradient boosting": lambda f: order_gb[f.name],
    "logistic / predicted cost": lambda f: order_lr_cost[f.name],
}
Ts = (0.25, 0.5, 1, 2, 5, 10)
print(f"\n-- per-file recall of {KIND} strings on the test files, by decoding budget --")
print(f"{'order':<28}" + "".join(f"{T:>7}s" for T in Ts))
for name, o in orders.items():
    print(f"{name:<28}" + "".join(f"{per_file_recall(test, o, T):8.3f}" for T in Ts))
