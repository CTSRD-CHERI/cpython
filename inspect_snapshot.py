# inspect_snapshot.py
import tracemalloc

snapshot = tracemalloc.Snapshot.load("tracemalloc_snapshot.snap")
top_stats = snapshot.statistics("traceback")

print("[ Top 10 memory-consuming tracebacks ]")
for i, stat in enumerate(top_stats[:10], 1):
    print(f"#{i}: {stat.size / 1024:.1f} KiB")
    for line in stat.traceback.format():
        print(f"    {line}")
