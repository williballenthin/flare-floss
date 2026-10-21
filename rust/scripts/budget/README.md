# how long to emulate decoding routines

The scripts behind "How long to emulate decoding routines" in `doc/EVALUATION.md`.

1. Emulate every candidate of each file, recording what each routine costs and finds
   (`analysis.decoding_routines` in floss-rs's JSON output):

       ./run_curve.sh ../../target/release/floss-rs path/to/capa-testfiles files.txt curve 60

2. Parse the run once (this checks which strings are in the files, so it needs the samples):

       export CAPA_TESTFILES=path/to/capa-testfiles BUDGET_DATA=budget.pkl
       python3 sim.py curve --save

3. Replay stopping rules offline. Routines are emulated independently, so a rule's
   value is the union of the strings from the routines it would run, and its cost the
   sum of their times:

       python3 final.py        # the budget curves, 1 thread and 4 (simulated), by file size
       python3 policies.py train|test   # adaptive rules: the pareto frontier, on each half of the files
       python3 grid.py         # budgets vs dry spells, side by side
       python3 signals.py      # do dry spells, score cliffs, or the top 20 predict what's left?
       python3 where.py curve  # strings by candidate rank and score
       python3 order.py        # does the order of candidates matter?
       python3 rank_study.py   # can a model of the features rank candidates better? (needs numpy, scikit-learn)

4. Score real runs (made with the usual `-j --no static` options) against emulating every candidate:

       python3 score.py run-dir...

Strings count as *novel* if they're not in the file as-is and not mostly static text
from the file, and as *meaningful* if they're also at least 6 characters, mostly letters,
and not repetitive (`sim.py`).

## ranking candidates

The scripts behind "Ranking candidates" in `doc/EVALUATION.md`.

1. Dump the features of every candidate, one JSON-lines file per sample:

       cargo build --release --example candidate_features
       for f in $(cat files.txt); do ../../target/release/examples/candidate_features "path/to/capa-testfiles/$f" > "features/$f.jsonl"; done

2. Compare features and scores against what each routine found (with `$BUDGET_DATA` as above):

       export FEATURES_DIR=features
       python3 features_study.py features words   # how well each feature ranks a file's routines
       python3 hand_scores.py words               # FLOSS's score, with one change at a time
       python3 score_study.py words               # cross-validated models (needs numpy, scikit-learn)
       python3 fit_score.py words                 # a small linear score fitted on half of the files

   `words` are the *text-like* strings: novel, meaningful, and reading like text by
   a character trigram model of the samples' static strings (`sim.Trigrams`).

3. `floss-size-score.patch` is the new score for Python FLOSS (against v4.0.0a2).
   To compare Python FLOSS runs (decoded strings) with and without it:

       python3 py_compare.py run-without/ run-with/
