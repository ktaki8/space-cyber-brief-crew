"""Small, dependency-free statistics for the evaluation."""
import math
import random


def _binom_tail(n, k, p):
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k, n + 1))


def clopper_pearson(k, n, alpha=0.05):
    """Exact two-sided interval, as used for the pilot's 11.6% and 30.8% bounds."""
    if n == 0:
        return (0.0, 1.0)

    def solve(f):
        lo, hi = 0.0, 1.0
        for _ in range(100):
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if f(mid) else (lo, mid)
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else solve(lambda p: _binom_tail(n, k, p) < alpha / 2)
    upper = 1.0 if k == n else solve(lambda p: 1 - _binom_tail(n, k + 1, p) > alpha / 2)
    return lower, upper


def fisher_two_sided(a, b, c, d):
    """Fisher exact for [[a, b], [c, d]], summing tables no more likely than observed."""
    r1, r2, c1, n = a + b, c + d, a + c, a + b + c + d

    def prob(x):
        return math.comb(r1, x) * math.comb(r2, c1 - x) / math.comb(n, c1)

    observed = prob(a)
    low, high = max(0, c1 - r2), min(r1, c1)
    return min(1.0, sum(prob(x) for x in range(low, high + 1) if prob(x) <= observed * (1 + 1e-9)))


def cohen_kappa(left, right):
    pairs = [(a, b) for a, b in zip(left, right)]
    n = len(pairs)
    if not n:
        return float("nan")
    labels = {x for pair in pairs for x in pair}
    observed = sum(a == b for a, b in pairs) / n
    expected = sum(sum(a == x for a, _ in pairs) * sum(b == x for _, b in pairs) for x in labels) / n ** 2
    return 1.0 if expected == 1 else (observed - expected) / (1 - expected)


def cluster_bootstrap(rows, cluster, statistic, reps=4000, seed=20261103):
    """Percentile interval resampling whole clusters. Runs within a document
    are not independent, so resampling them singly would overstate precision."""
    rng = random.Random(seed)
    groups = {}
    for row in rows:
        groups.setdefault(row[cluster], []).append(row)
    keys = sorted(groups)
    values = []
    for _ in range(reps):
        sample = [r for k in rng.choices(keys, k=len(keys)) for r in groups[k]]
        value = statistic(sample)
        if value is not None and value == value:
            values.append(value)
    if not values:
        return (float("nan"), float("nan"))
    values.sort()
    return values[int(0.025 * (len(values) - 1))], values[int(0.975 * (len(values) - 1))]
