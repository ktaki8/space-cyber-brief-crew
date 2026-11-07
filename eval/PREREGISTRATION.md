# Analysis plan

Date this file and commit it before the first real run. A public timestamp is
what makes it a plan rather than a story told afterward.

**Model:** one pinned model, named in the manifest. Temperature 0.2, seed 20261103.

## Primary questions

1. Does the rule block reduce fabricated assertions when tools are held fixed?
   (`A_factorial`, rules main effect, coded claims.)
2. Does the rule block cost supported-claim recall? (Same comparison, fact recall.)
3. Does tool availability change epistemic errors at all? We expect it may not,
   which would separate the execution boundary from the content result.
4. Can document text change a finished brief in the governed pipeline, and does
   the sanitizer help against prose written for human readers?
   (`D_attacks`. We expect it helps on `machine` and not on `prose`.)

## Secondary

Single-rule ablations (`B_ablation`), comparators (`C_comparators`), by-document
variation, and the rate of correct claims with a wrong reference.

## Rules set in advance

- Every run counts. A failed run stays in the denominator as a failure of that run.
- Results are given per bundle and per document before any pooled figure.
- Intervals resample whole bundles. With four bundles they are rough, and we say so.
- Zero observed failures is reported as an interval, never as "no risk".
- Any change to prompts, rules, corpus, or the codebook after the first real run
  starts a new batch and is reported as such.
- Exploratory findings are labeled exploratory.

## Not tested by this kit

Human decision quality (see `protocols/analyst_crossover.md`), operating-system
confinement, and export or publishing integrations. The repo has none of these
integrations today, so anyone adding one must extend `D_attacks` to cover it.
