# inspect_snapshot.py
import tracemalloc
import argparse
import sys


def main():
    p = argparse.ArgumentParser(
        description="Load and inspect a tracemalloc snapshot file"
    )
    p.add_argument(
        "snapshot_file",
        help="path to the .snap file produced by tracemalloc"
    )
    args = p.parse_args()

    try:
        snapshot = tracemalloc.Snapshot.load(args.snapshot_file)
    except FileNotFoundError:
        sys.exit(f"Error: '{args.snapshot_file}' not found")

    top_stats = snapshot.statistics("traceback")
    
    print("[ Top 10 memory-consuming tracebacks ]")
    for i, stat in enumerate(top_stats[:10], 1):
        print(f"#{i}: {stat.size / 1024:.1f} KiB")
        for line in stat.traceback.format():
            print(f"    {line}")


if __name__ == "__main__":
    main()
