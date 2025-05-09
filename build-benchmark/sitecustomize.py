# sitecustomize.py
import tracemalloc
import resource
import os, sys
import atexit

# Start tracking memory allocations
tracemalloc.start()

# Automatically save a snapshot at exit


def save_snapshot():
    snapshot = tracemalloc.take_snapshot()
    fn = os.environ.get("SNAPFILE", "tracemalloc_snapshot.snap")
    snapshot.dump(fn)
    print(f"[tracemalloc] Snapshot saved to {fn}", file=sys.stderr)


def report_max_rss():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    # On Linux and FreeBSD, ru_maxrss is already in kilobytes
    rss_kb = usage.ru_maxrss
    print(f"[ max RSS ] {rss_kb} KB", file=sys.stderr)


#atexit.register(save_snapshot)
atexit.register(report_max_rss)
