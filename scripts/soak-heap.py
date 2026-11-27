"""Live heap against RSS in a soak run of a node built with `heap-stats` (PD-233).

    python scripts/soak-heap.py <report.json> <work dir>

Joins the `heap summary` log lines of the node (`bins/rustegond/src/heap_stats.rs`, one every
10 s) with the samples of the soak report, from the moment the block cache is full. Prints the
live heap, the RSS and their distance per flush cycle, a least-squares fit of each on the
memtable gauge and on time (the trend in MiB/hour), the same per allocation size class, and the
largest RSS moves. A live heap that grows names the size class to look for; RSS growing with a
flat live heap is memory the allocator keeps.
"""
import bisect
import datetime as dt
import glob
import json
import sys

M = 1 << 20
# Size classes that follow the memtable cycle (skip-list nodes, keys, values).
MEMTABLE_CLASSES = {5, 6, 7, 11, 12}
r = json.load(open(sys.argv[1]))
t0 = r["start_unix_ms"]
heap = []
for f in glob.glob(sys.argv[2] + "/**/*.log", recursive=True):
    for line in open(f, encoding="utf-8"):
        if "heap summary" not in line:
            continue
        j = json.loads(line)
        t = dt.datetime.fromisoformat(j["ts"].replace("Z", "+00:00")).timestamp() * 1000 - t0
        classes = {}
        for part in j["by_class"].split():
            c, rest = part.split(":")
            classes[int(c)] = int(rest.split("/")[0])
        heap.append((t, int(j["live_bytes"]), classes))
if not heap:
    sys.exit("no `heap summary` line under " + sys.argv[2] + ": was the node built with heap-stats?")
heap.sort(key=lambda h: h[0])
times = [h[0] for h in heap]

rows = []
for s in r["samples"]:
    k = bisect.bisect_left(times, s["t_ms"])
    k = min(k, len(heap) - 1)
    if k > 0 and abs(times[k - 1] - s["t_ms"]) < abs(times[k] - s["t_ms"]):
        k -= 1
    if abs(times[k] - s["t_ms"]) > 8000:
        continue
    _, live, classes = heap[k]
    steady = sum(b for c, b in classes.items() if c not in MEMTABLE_CLASSES)
    rows.append(
        dict(
            classes=classes,
            t=s["t_ms"] / 1000,
            rss=s["rss_bytes"] / M,
            priv=s.get("private_bytes", 0) / M,
            live=live / M,
            steady=steady / M,
            mem=s["memtable_bytes"] / M,
            cache=s["block_cache_bytes"] / M,
            fl=s["flushes"],
            comp=s["compactions"],
            sst=s["sst_files"],
        )
    )
if not rows:
    sys.exit("no sample of the report is within 8 s of a `heap summary` line: report and work dir of different runs?")

# "Full": within 1 % of the largest block cache seen, so the fill does not count as growth.
cache_full = 0.99 * max(x["cache"] for x in rows)
full = [x for x in rows if x["cache"] >= cache_full]
print(len(rows), "joined samples,", len(full), "with a full cache, from t = %d s" % full[0]["t"])

print()
print("per flush cycle (cache full), MiB; `steady` = the size classes outside the memtable cycle")
print("flushes   t_s | live min  max | steady min  max | rss min  max | priv max | rss-live at live max, min | comp sst")
cycles = {}
for x in full:
    cycles.setdefault(x["fl"], []).append(x)
# One line per cycle up to 40 cycles, then every n-th: a 12 h run has about 270.
every = max(1, len(cycles) // 40)
for i, fl in enumerate(sorted(cycles)):
    if i % every and i != len(cycles) - 1:
        continue
    c = cycles[fl]
    peak = max(c, key=lambda x: x["live"])
    trough = min(c, key=lambda x: x["live"])
    print(
        "%7d %5d | %8d %4d | %10d %4d | %7d %4d | %8d | %12d %11d | %4d %3d"
        % (
            fl,
            c[0]["t"],
            trough["live"],
            peak["live"],
            min(x["steady"] for x in c),
            max(x["steady"] for x in c),
            min(x["rss"] for x in c),
            max(x["rss"] for x in c),
            max(x["priv"] for x in c),
            peak["rss"] - peak["live"],
            trough["rss"] - trough["live"],
            c[-1]["comp"],
            c[-1]["sst"],
        )
    )


def fit(ys, xs_list):
    """Least squares of y on the columns of xs_list plus a constant (normal equations, Gauss)."""
    n = len(ys)
    cols = [[1.0] * n] + xs_list
    k = len(cols)
    a = [[sum(cols[i][m] * cols[j][m] for m in range(n)) for j in range(k)] for i in range(k)]
    b = [sum(cols[i][m] * ys[m] for m in range(n)) for i in range(k)]
    for i in range(k):
        p = max(range(i, k), key=lambda q: abs(a[q][i]))
        a[i], a[p] = a[p], a[i]
        b[i], b[p] = b[p], b[i]
        for q in range(i + 1, k):
            f = a[q][i] / a[i][i]
            for j in range(i, k):
                a[q][j] -= f * a[i][j]
            b[q] -= f * b[i]
    coef = [0.0] * k
    for i in reversed(range(k)):
        coef[i] = (b[i] - sum(a[i][j] * coef[j] for j in range(i + 1, k))) / a[i][i]
    res = [ys[m] - sum(coef[i] * cols[i][m] for i in range(k)) for m in range(n)]
    sd = (sum(e * e for e in res) / max(1, n - k)) ** 0.5
    return coef, sd


def trend(part, value):
    """Fit of `value` on the memtable gauge and on the hours of `part`."""
    return fit([value(x) for x in part], [[x["mem"] for x in part], [x["t"] / 3600 for x in part]])


span = (full[-1]["t"] - full[0]["t"]) / 3600
print()
print("fit on the memtable gauge and on time, %d samples over %.2f h" % (len(full), span))
for name, value in (
    ("live", lambda x: x["live"]),
    ("steady", lambda x: x["steady"]),
    # Live memory that is neither memtable nor block cache: what a leak would be in.
    ("steady - cache", lambda x: x["steady"] - x["cache"]),
    ("rss", lambda x: x["rss"]),
    ("priv", lambda x: x["priv"]),
    ("rss - live", lambda x: x["rss"] - x["live"]),
):
    coef, sd = trend(full, value)
    print(
        "%-14s = %6.1f %+.2f x memtable %+6.1f MiB/hour   (residual sd %.1f MiB)"
        % (name, coef[0], coef[1], coef[2], sd)
    )

print()
print("the same per quarter of the run: where a trend starts or stops")
quarter = max(1, len(full) // 4)
for q in range(4):
    part = full[q * quarter :] if q == 3 else full[q * quarter : (q + 1) * quarter]
    if len(part) < 8:
        continue
    print(
        "t %6d-%6d s: live %+6.1f  steady - cache %+6.1f  rss %+6.1f  rss - live %+6.1f MiB/hour   sst %d -> %d"
        % (
            part[0]["t"],
            part[-1]["t"],
            trend(part, lambda x: x["live"])[0][2],
            trend(part, lambda x: x["steady"] - x["cache"])[0][2],
            trend(part, lambda x: x["rss"])[0][2],
            trend(part, lambda x: x["rss"] - x["live"])[0][2],
            part[0]["sst"],
            part[-1]["sst"],
        )
    )

print()
print("per size class (cache full): MiB at the first and last sample, fit on memtable and time")
for c in sorted({c for x in full for c in x["classes"]}):
    if max(x["classes"].get(c, 0) for x in full) < M // 2:
        continue
    coef, sd = trend(full, lambda x, c=c: x["classes"].get(c, 0) / M)
    print(
        "class %2d (%8d+ B): %6.1f -> %6.1f   %+.2f x memtable  %+6.1f MiB/hour  (sd %.1f)"
        % (
            c,
            0 if c == 0 else 1 << (c - 1),
            full[0]["classes"].get(c, 0) / M,
            full[-1]["classes"].get(c, 0) / M,
            coef[1],
            coef[2],
            sd,
        )
    )

print()
print("largest rss moves between two samples (cache full)")
moves = sorted(
    ((full[i]["rss"] - full[i - 1]["rss"], i) for i in range(1, len(full))), key=lambda m: -abs(m[0])
)[:8]
for d, i in sorted(moves, key=lambda m: m[1]):
    a, b = full[i - 1], full[i]
    print(
        "t %6d s  rss %4d -> %4d (%+d)   live %4d -> %4d (%+d)   memtable %2d -> %2d  flushes %d -> %d  compactions %d -> %d"
        % (b["t"], a["rss"], b["rss"], d, a["live"], b["live"], b["live"] - a["live"], a["mem"], b["mem"], a["fl"], b["fl"], a["comp"], b["comp"])
    )
