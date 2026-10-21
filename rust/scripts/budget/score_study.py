"""can a score built from candidate features find more strings with FLOSS's top 20, or within a time budget?
5-fold cross-validation by file: each model is trained on 4/5 of the files and ranks the candidates of the rest.
needs numpy and scikit-learn. usage: score_study.py [good|novel]"""
import os, sys, math, hashlib, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features_study import load, feature_names, top_k_recall, budget_recall
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier

KIND = sys.argv[1] if len(sys.argv) > 1 else "good"
data = load(KIND)
NAMES = [n for n in feature_names(data) if n not in ("score",)]


def vec(f, names):
    return [math.log1p(f.get(n, 0)) for n in names]


def fold(name):
    return int(hashlib.sha256(name.encode()).hexdigest(), 16) % 5


def cross_validated(make, names, label=lambda r: bool(r[KIND])):
    """attach each routine's out-of-fold prediction to its features, as `pred`."""
    for k in range(5):
        train = [r for n, rows in data if fold(n) != k for r in rows]
        X = np.array([vec(r["f"], names) for r in train])
        y = np.array([label(r) for r in train])
        model = make().fit(X, y)
        for n, rows in data:
            if fold(n) == k and rows:
                p = model.predict_proba(np.array([vec(r["f"], names) for r in rows]))[:, 1]
                for r, v in zip(rows, p):
                    r["f"]["pred"] = float(v)
    return model


def report(name, score):
    t20 = top_k_recall(data, score, KIND)
    t50 = top_k_recall(data, score, KIND, 50)
    b = [budget_recall(data, score, KIND, T) for T in (0.25, 0.5, 1, 2)]
    print(f"{name:<46} {t20:7.3f} {t50:7.3f} " + " ".join(f"{v:7.3f}" for v in b), flush=True)


print(f"{len(data)} files; share of each file's {KIND} strings found")
print(f"{'score':<46} {'top 20':>7} {'top 50':>7} " + " ".join(f"{T:>6}s" for T in (0.25, 0.5, 1, 2)))
report("FLOSS score", lambda f: f["score"])
report("instructions", lambda f: f.get("instructions", 0))

lr = cross_validated(lambda: LogisticRegression(max_iter=3000, C=0.3, class_weight="balanced"), NAMES)
report("logistic regression, all features", lambda f: f["pred"])
print("   coefficients (last fold):", ", ".join(f"{n} {c:+.2f}" for n, c in sorted(zip(NAMES, lr.coef_[0]), key=lambda t: -abs(t[1]))[:14]))

cross_validated(lambda: GradientBoostingClassifier(random_state=0, n_estimators=200, max_depth=3), NAMES)
report("gradient boosting, all features", lambda f: f["pred"])

floss_names = ["blocks", "instructions", "arguments", "calls_to", "loops", "tight_loops", "tight_function",
               "nzxor", "shifts", "movs", "nzxor_tight_loop", "nzxor_loop"]
cross_validated(lambda: GradientBoostingClassifier(random_state=0, n_estimators=200, max_depth=3), floss_names)
report("gradient boosting, FLOSS's features only", lambda f: f["pred"])
