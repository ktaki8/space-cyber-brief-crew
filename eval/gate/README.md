# Keyword gate audit

`labeled_items.csv` is a 58-item stress set written for this audit (19 relevant
items in each half, plus hard negatives). It oversamples hard cases, so the
rates describe those cases, not performance on a real feed. One author wrote
the labels. A second labeler should review them before these numbers are published.

| Gate: any space term | Recall, dev half | Recall, held-out half | Recall, all |
|---|---|---|---|
| Before | 4/19 (21%) | 5/19 (26%) | 9/38 (24%) |
| After adding terms from the dev half | 16/19 (84%) | 6/19 (32%) | 22/38 (58%) |

The gap between 84% and 32% is the finding. Adding names fixed the names on the
list and barely moved anything else, so a keyword list cannot be the recall
control. Precision is low too: 9 of the 10 false-friend items passed (Orbit
apps, GPS pet trackers, SDR sales tools). The ordinary-IT items all stayed out.

The four image-only items contain no usable text, so no keyword can catch them.
Those items now route to a person (`needs_human_triage`) instead of being scored.

The held-out misses printed by `audit_gate.py` are now known, so this half is
spent. Write a new held-out set before reporting another improvement.
