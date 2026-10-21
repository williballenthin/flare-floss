"""replay candidate-decoding stopping policies offline, from a run that emulated (nearly) every candidate.

usage: sim.py RUN_DIR [--split train|test|all]

each routine's strings and cost are recorded in the run's JSON (analysis.decoding_routines),
so a policy that picks a prefix of the emulation order can be evaluated exactly:
its value is the union of the novel strings from the routines it runs, its cost the sum of their seconds.
"""
import os, sys, json, pathlib, pickle, re, hashlib, statistics

SAMPLES = pathlib.Path(os.environ.get("CAPA_TESTFILES", "capa-testfiles"))
# the parsed run (see --save), which the other scripts read.
DATA = os.environ.get("BUDGET_DATA", "budget.pkl")


def is_static(buf, s):
    try:
        return s.encode("latin-1") in buf or s.encode("utf-16le") in buf
    except UnicodeEncodeError:
        return False


GRAM = 6


def static_grams(buf):
    """the 6-character pieces of the file's static strings (ASCII and UTF-16LE)."""
    texts = [m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e\t]{4,}", buf)]
    texts += [m.group()[::2].decode("latin-1") for m in re.finditer(rb"(?:[\x20-\x7e\t]\x00){4,}", buf)]
    return {t[i:i + GRAM] for t in texts for i in range(len(t) - GRAM + 1)}


def derived(grams, s):
    """is most of the string static text from the file, like a format string filled in?"""
    covered = [False] * len(s)
    for i in range(len(s) - GRAM + 1):
        if s[i:i + GRAM] in grams:
            covered[i:i + GRAM] = [True] * GRAM
    return sum(covered) >= 0.4 * len(s)


def meaningful(s):
    """a rough filter for strings a person would want: not short, mostly letters, not repetitive."""
    if len(s) < 6:
        return False
    letters = sum(c.isalpha() for c in s)
    if letters < 0.5 * len(s):
        return False
    if len(set(s)) < 5:
        return False
    if max(s.count(c) for c in set(s)) > 0.35 * len(s):
        return False
    return True


class File:
    def __init__(self, path):
        self.name = path.name[:-5]
        d = json.loads(path.read_text())
        buf = (SAMPLES / self.name).read_bytes()
        a = d["analysis"]
        self.candidates = a["decoding_candidates"]
        rs = a["decoding_routines"]
        decoded = d["strings"]["decoded_strings"]
        n = sum(r["strings"] for r in rs)
        routine_part, elsewhere = decoded[:n], decoded[n:]

        # strings found anyway, by the other analyses (or present in the file) aren't credited to decoding.
        base = {s["string"] for k in ("stack_strings", "tight_strings") for s in d["strings"][k]}
        base |= {s["string"] for s in elsewhere}
        grams = static_grams(buf)

        self.routines = []
        i = 0
        for r in rs:
            strings = {s["string"] for s in routine_part[i:i + r["strings"]]}
            i += r["strings"]
            novel = {s for s in strings if s not in base and not is_static(buf, s) and not derived(grams, s)}
            self.routines.append({
                "address": r["address"], "features": r.get("features", {}),
                "score": r["score"], "required": r["required"], "seconds": r["seconds"], "calls": r["calls"],
                "all": strings, "novel": novel, "good": {s for s in novel if meaningful(s)},
            })
        self.complete = len(rs) == self.candidates
        rt = d["metadata"]["runtime"]
        self.fixed = rt["total"] - rt["decoded_strings"]   # everything but decoding
        self.required = sum(r["required"] for r in self.routines)

    def oracle(self, kind="novel"):
        out = set()
        for r in self.routines:
            out |= r[kind]
        return out


def evaluate(files, policy, kind="novel"):
    """total strings recovered (as a fraction of the oracle), and costs, for a policy over files."""
    got = total = 0
    times = []
    recalls = []
    for f in files:
        k = policy(f)
        found = set()
        for r in f.routines[:k]:
            found |= r[kind]
        got += len(found)
        total += len(f.oracle(kind))
        if f.oracle(kind):
            recalls.append(len(found) / len(f.oracle(kind)))
        times.append(f.fixed + sum(r["seconds"] for r in f.routines[:k]))
    times.sort()
    return {
        "recall": got / total if total else 1.0,
        "file_recall": statistics.mean(recalls) if recalls else 1.0,
        "strings": got,
        "total_time": sum(times),
        "mean": statistics.mean(times),
        "p95": times[int(0.95 * (len(times) - 1))],
        "max": times[-1],
    }


# --- policies: each returns how many routines (a prefix of the emulation order) to run ---

def budget(T):
    """the current rule: all required routines, then extra ones while decoding has taken less than T."""
    def p(f):
        t = 0.0
        for i, r in enumerate(f.routines):
            if not r["required"] and t >= T:
                return i
            t += r["seconds"]
        return len(f.routines)
    p.__name__ = f"budget({T})"
    return p


def top_k(K):
    def p(f):
        return min(len(f.routines), max(K, 0))
    p.__name__ = f"top({K})"
    return p


def load(run, split="all"):
    files = []
    for path in sorted(pathlib.Path(run).glob("*.json")):
        try:
            f = File(path)
        except Exception:
            continue
        if not f.routines:
            continue
        h = int(hashlib.sha256(f.name.encode()).hexdigest(), 16) % 2
        if split == "train" and h != 0 or split == "test" and h != 1:
            continue
        files.append(f)
    return files


if __name__ == "__main__":
    run = sys.argv[1]
    split = sys.argv[sys.argv.index("--split") + 1] if "--split" in sys.argv else "all"
    files = load(run, split)
    if "--save" in sys.argv:
        pickle.dump(files, open(DATA, "wb"))
    print(f"{len(files)} files, {sum(f.complete for f in files)} with every candidate emulated")
    for kind in ("novel", "good"):
        print(f"\n== {kind}: oracle {sum(len(f.oracle(kind)) for f in files)} strings")
        for T in [0, 0.25, 0.5, 1, 2, 3, 5, 10, 20, 30, 60]:
            e = evaluate(files, budget(T), kind)
            print(f"  budget {T:>5}s  recall {e['recall']:.3f}  per-file {e['file_recall']:.3f}  strings {e['strings']:5d}  "
                  f"total {e['total_time']:7.0f}s  mean {e['mean']:5.2f}s  p95 {e['p95']:5.1f}s  max {e['max']:5.1f}s")
