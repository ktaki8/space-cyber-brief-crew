# Analyst crossover study

Purpose: test whether review of a governed brief improves analyst decisions. The
pipeline evaluation cannot answer that, and it should not be claimed without this
study. It needs human participants, so check with CMU's IRB before recruiting.

**Participants:** 12 or more analysts or trained students. Decide the final number
with a power estimate once the pilot gives you variance.

**Design:** two-period crossover. Each analyst reviews one set of briefs from the
unguided single agent and one set from the full stack. Provenance display is on
in both. Order and document set are counterbalanced. Analysts do not know the arm.

**Materials:** briefs from saved runs, seeded with known errors: a fabricated ID,
a wrong reference, a dropped warning, and an injected attribution. Include clean
briefs so that analysts are not simply hunting for planted errors.

**Measures:** hazards missed, false rejections of correct claims, review minutes,
override count, and NASA-TLX workload. Also ask whether each brief would be released.

**Analysis:** mixed-effects model with analyst and document as random effects and
period as a fixed effect. Report missed hazards together with review time, because
a faster review that misses more is not an improvement.
