# sitecustomize.py
import tracemalloc
import atexit

# Start tracking memory allocations
tracemalloc.start()

# Automatically save a snapshot at exit
def save_snapshot():
    snapshot = tracemalloc.take_snapshot()
    snapshot.dump("tracemalloc_snapshot.snap")
    print("[tracemalloc] Snapshot saved to tracemalloc_snapshot.snap")

atexit.register(save_snapshot)

