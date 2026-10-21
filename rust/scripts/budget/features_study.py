"""which static features of a candidate predict that it decodes strings?

joins the features from `examples/candidate_features` (one JSON-lines file per sample, in $FEATURES_DIR)
with what each routine found in the all-candidates run ($BUDGET_DATA, see sim.py), then:
  - for each feature, how well it ranks the routines of a file (the AUC within each file, averaged over files),
    and how much more often routines with the feature find strings than those without;
  - for candidate scores, the share of each file's strings found by FLOSS's top 20, and within time budgets.
usage: features_study.py [features|scores] [good|novel]
"""
import os, sys, json, math, pathlib, pickle, statistics, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim import DATA, File  # noqa

FEATURES_DIR = pathlib.Path(os.environ.get("FEATURES_DIR", "features"))


def load(kind="good"):
    files = pickle.load(open(DATA, "rb"))
    out = []
    for f in files:
        path = FEATURES_DIR / f"{f.name}.jsonl"
        if not path.exists():
            continue
        feats = {}
        for line in path.read_text().splitlines():
            row = json.loads(line)
            feats[row["address"]] = row
        rows = []
        for r in f.routines:
            ft = feats.get(r["address"])
            if ft is None:
                continue
            rows.append({"f": ft, "required_tight": bool(ft.get("tight_function")), "seconds": r["seconds"],
                         "good": r["good"], "novel": r["novel"], "words": r["words"]})
        out.append((f.name, rows))
    return out


def auc(scores, labels):
    """the chance a random positive scores above a random negative (ties count half)."""
    pos = [s for s, l in zip(scores, labels) if l]
    neg = [s for s, l in zip(scores, labels) if not l]
    if not pos or not neg:
        return None
    ranked = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg])
    # rank-sum with ties averaged
    rank_sum, i = 0.0, 0
    while i < len(ranked):
        j = i
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        avg = (i + j + 1) / 2
        rank_sum += avg * sum(1 for k in range(i, j) if ranked[k][1])
        i = j
    return (rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def feature_names(data):
    names = set()
    for _, rows in data:
        for r in rows:
            names |= {k for k, v in r["f"].items() if isinstance(v, (int, float)) and k != "address"}
    return sorted(names)


def study_features(data, kind):
    names = feature_names(data)
    print(f"{'feature':<24} {'AUC within files':>16} {'files':>6}   {'yield rate with / without':>26}  share of routines with it")
    rows_all = [r for _, rows in data for r in rows]
    for n in names:
        aucs = []
        for _, rows in data:
            a = auc([r["f"].get(n, 0) for r in rows], [bool(r[kind]) for r in rows])
            if a is not None:
                aucs.append(a)
        with_ = [r for r in rows_all if r["f"].get(n, 0) > 0]
        without = [r for r in rows_all if not r["f"].get(n, 0) > 0]
        rate = lambda rs: sum(bool(r[kind]) for r in rs) / max(len(rs), 1)
        print(f"{n:<24} {statistics.mean(aucs):16.3f} {len(aucs):6d}   {100 * rate(with_):11.2f}% / {100 * rate(without):5.2f}%"
              f"   {len(with_) / len(rows_all):6.1%}")


def top_k_recall(data, score, kind, k=20):
    """the share of each file's strings found by the top k (plus tight functions, like FLOSS)."""
    out = []
    for _, rows in data:
        oracle = set().union(*(r[kind] for r in rows)) if rows else set()
        if not oracle:
            continue
        ranked = sorted(rows, key=lambda r: -score(r["f"]))
        chosen = ranked[:k] + [r for r in ranked[k:] if r["required_tight"]]
        found = set().union(*(r[kind] for r in chosen))
        out.append(len(found) / len(oracle))
    return statistics.mean(out)


def budget_recall(data, score, kind, T):
    out = []
    for _, rows in data:
        oracle = set().union(*(r[kind] for r in rows)) if rows else set()
        if not oracle:
            continue
        ranked = sorted(rows, key=lambda r: -score(r["f"]))
        t, found = 0.0, set()
        for r in ranked:
            if t >= T:
                break
            t += r["seconds"]; found |= r[kind]
        out.append(len(found) / len(oracle))
    return statistics.mean(out)


def report(data, scores, kind):
    print(f"{'score':<44} {'top 20':>7} {'top 50':>7} " + " ".join(f"{T:>6}s" for T in (0.25, 0.5, 1, 2)))
    for name, s in scores:
        print(f"{name:<44} {top_k_recall(data, s, kind):7.3f} {top_k_recall(data, s, kind, 50):7.3f} "
              + " ".join(f"{budget_recall(data, s, kind, T):7.3f}" for T in (0.25, 0.5, 1, 2)))


def split(data, which):
    want = 0 if which == "train" else 1
    return [d for d in data if int(hashlib.sha256(d[0].encode()).hexdigest(), 16) % 2 == want]


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "features"
    kind = sys.argv[2] if len(sys.argv) > 2 else "good"
    data = load(kind)
    print(f"{len(data)} files, {sum(len(r) for _, r in data)} routines, "
          f"{sum(1 for _, rows in data for r in rows if r[kind])} yield {kind} strings")
    if mode == "features":
        study_features(data, kind)
    else:
        report(data, [("FLOSS score", lambda f: f["score"])], kind)
