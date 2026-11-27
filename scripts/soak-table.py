"""Per-window table of a soak report (PD-157, PD-233).

    python scripts/soak-table.py <report.json> [<work dir of the run>]

Columns: p99 of the window and of each operation (ms); operations >= 50 ms; node RSS and RSS
minus block cache and memtables (MiB); host CPU busy share and the node's CPU (% of a core);
block-cache hits per operation; with the work dir, log syncs per second, their mean (us) and
longest (ms) from the node's `file-system summary` log lines; SST files; the busiest process
that is neither the node nor the runner, in cores (a window with one above about 1 core, or a
host share far above the others, was disturbed from outside and does not judge the node).
With `host.jsonl` in the work dir (scripts/soak-host.ps1): seconds on battery; MiB/s written
to the disk by everything and the mean ms of a write request; the busiest other process by CPU
(peak cores in a sample, protected processes included) and by MiB/s written over the window.
"""
import collections
import datetime as dt
import glob
import json
import os
import sys

r = json.load(open(sys.argv[1]))
t0 = r["start_unix_ms"]
W = r["duration_s"] * 1000 // 24
S = [s for s in r["samples"] if isinstance(s.get("cpu"), dict) and "ts" in s["cpu"]]
host = collections.defaultdict(list)
node = collections.defaultdict(float)
hits = collections.defaultdict(float)
span = collections.defaultdict(float)
other = collections.defaultdict(lambda: (0.0, ""))
for a, b in zip(S, S[1:]):
    w = b["t_ms"] // W
    d = b["cpu"]["ts"] - a["cpu"]["ts"]
    host[w].append(1 - (b["cpu"]["idle"] - a["cpu"]["idle"]) / d)
    node[w] += b["cpu"]["cpu"].get("rustegond", 0) - a["cpu"]["cpu"].get("rustegond", 0)
    hits[w] += b["cache_hits"] - a["cache_hits"]
    span[w] += (b["t_ms"] - a["t_ms"]) / 1000
    for name, cpu in b["cpu"]["cpu"].items():
        if name not in ("rustegond", "soak"):
            cores = (cpu - a["cpu"]["cpu"].get(name, 0)) / (d / 1e7)
            other[w] = max(other[w], (cores, name))
fs = collections.defaultdict(list)
if len(sys.argv) > 2:
    for f in glob.glob(sys.argv[2] + "/**/*.log", recursive=True):
        for line in open(f, encoding="utf-8"):
            if "file-system summary" not in line:
                continue
            j = json.loads(line)
            t = dt.datetime.fromisoformat(j["ts"].replace("Z", "+00:00")).timestamp() * 1000 - t0
            if t >= 0:
                fs[int(t // W)].append(j)
mon = collections.defaultdict(list)
if len(sys.argv) > 2 and os.path.exists(sys.argv[2] + "/host.jsonl"):
    for line in open(sys.argv[2] + "/host.jsonl", encoding="utf-8"):
        j = json.loads(line)
        if "dt" in j and 0 <= j["t"] - t0 < 24 * W:
            mon[int((j["t"] - t0) // W)].append(j)


def host_columns(lines):
    """Battery seconds, disk MiB/s and ms per write, busiest other process by CPU and by writes."""
    sec = max(1e-9, sum(j["dt"] for j in lines))
    wn = sum(j["disk"]["wn"] for j in lines)
    cpu, wr = (0.0, ""), collections.Counter()
    for j in lines:
        for name, (c, mib) in j["proc"].items():
            if name not in ("rustegond", "soak"):
                cpu = max(cpu, (c / j["dt"], name))
                wr[name] += mib
    name, mib = max(wr.items(), key=lambda kv: kv[1], default=("", 0.0))
    return " | %4d %5.1f %5.2f | %s %.1f | %s %.2f" % (
        sum(j["dt"] for j in lines if not j["ac"]),
        sum(j["disk"]["wb"] for j in lines) / sec / 2**20,
        sum(j["disk"]["wms"] * j["disk"]["wn"] for j in lines) / max(1, wn),
        cpu[1],
        cpu[0],
        name,
        mib / sec,
    )


slow = collections.Counter(int(s[0] // W) for s in r["slow_ops"])
ops = sum(w["ops"] for w in r["windows"])
print(
    "pass", r.get("pass"), "ops", ops,
    "slow>=50ms %.3f%%" % (100 * len(r["slow_ops"]) / max(1, ops)),
    "p99 of the run %s us" % r.get("p99_us_run", "n/a"),
)
for c in r["checks"]:
    if not c["ok"]:
        print("FAIL", c["check"])
print(
    "win p99 get qry upd rpl trf | slow | rss other | host% node% | hits/op "
    "| sync/s avg_us max_ms | sst | busiest other process"
    + (" | batt_s disk_MiB/s ms/write | busiest by cpu | by MiB/s written" if mon else "")
)
for w in r["windows"]:
    i = w["window"] - 1
    o = w["p99_us_by_op"]
    f = fs.get(i, [])
    sn = sum(x["sync_n"] for x in f)
    su = sum(x["sync_us"] for x in f)
    rss = w["rss_max_bytes"] >> 20
    rest = (
        w["rss_max_bytes"] - (w.get("block_cache_bytes") or 0) - (w.get("memtable_bytes") or 0)
    ) >> 20
    h = host.get(i, [0])
    sec = max(1e-9, span.get(i, 0))
    cores, name = other[i]
    print(
        "%2d %5.1f %4.1f %5.1f %4.1f %4.1f %5.1f | %4d | %4d %4d | %3.0f %4.0f | %6.0f "
        "| %4.0f %5.0f %4.0f | %s | %s %.1f"
        % (
            w["window"],
            w["p99_us"] / 1000,
            o["get"] / 1000,
            o["query"] / 1000,
            o["update"] / 1000,
            o["replace"] / 1000,
            o["transfer"] / 1000,
            slow.get(i, 0),
            rss,
            rest,
            100 * sum(h) / len(h),
            100 * node.get(i, 0) / sec,
            hits.get(i, 0) / sec / r["rate"],
            sn / max(1, len(f)) / 10,
            su / max(1, sn),
            max((x["sync_max_us"] for x in f), default=0) / 1000,
            w.get("sst_files"),
            name,
            cores,
        )
        + (host_columns(mon[i]) if mon.get(i) else "")
    )
