"""where do decoded strings come from: by candidate rank and by score."""
import os, sys, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim import load

files = load(sys.argv[1])
kind = sys.argv[2] if len(sys.argv) > 2 else "novel"
by_rank = collections.Counter(); t_rank = collections.Counter(); n_rank = collections.Counter()
by_score = collections.Counter(); t_score = collections.Counter(); n_score = collections.Counter()
rank_buckets = [(1, 20), (21, 50), (51, 100), (101, 200), (201, 500), (501, 10**9)]
score_buckets = [0.8, 0.6, 0.4, 0.2, 0.0000001, -1]
for f in files:
    seen = set()
    for i, r in enumerate(f.routines, 1):
        new = r[kind] - seen
        seen |= r[kind]
        rb = next(b for b in rank_buckets if b[0] <= i <= b[1])
        sb = next(b for b in score_buckets if r["score"] >= b)
        by_rank[rb] += len(new); t_rank[rb] += r["seconds"]; n_rank[rb] += 1
        by_score[sb] += len(new); t_score[sb] += r["seconds"]; n_score[sb] += 1
total = sum(by_rank.values())
print(f"{len(files)} files, {total} {kind} strings")
print("rank        routines  strings  share   seconds  strings/s")
for b in rank_buckets:
    print(f"{b[0]:>4}-{b[1] if b[1] < 10**9 else '':<6} {n_rank[b]:8d} {by_rank[b]:8d} {by_rank[b]/total:6.1%} {t_rank[b]:9.1f} {by_rank[b]/max(t_rank[b],1e-9):9.1f}")
print("score>=     routines  strings  share   seconds  strings/s")
for b in score_buckets:
    print(f"{b:>8} {n_score[b]:10d} {by_score[b]:8d} {by_score[b]/total:6.1%} {t_score[b]:9.1f} {by_score[b]/max(t_score[b],1e-9):9.1f}")
