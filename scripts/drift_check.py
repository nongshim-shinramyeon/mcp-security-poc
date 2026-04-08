import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List


ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "security-baseline" / "drift_baseline.json"
REPORT_DIR = ROOT / "artifacts" / "drift"
REPORT_PATH = REPORT_DIR / "drift_report.json"

TRACKED_PATTERNS = (
    "docker-compose.yml",
    "README.md",
    "agent/*.py",
    "mcp-server/*.py",
    "proxy/*",
    "scripts/*.py",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_tracked_files() -> Iterable[Path]:
    seen = set()
    for pattern in TRACKED_PATTERNS:
        for path in ROOT.glob(pattern):
            if not path.is_file():
                continue
            if path.name.endswith(".pyc"):
                continue
            rel = path.relative_to(ROOT)
            if rel in seen:
                continue
            seen.add(rel)
            yield path


def collect_snapshot() -> List[Dict[str, object]]:
    snapshot = []
    for path in sorted(iter_tracked_files()):
        stat = path.stat()
        snapshot.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": sha256_file(path),
                "size": stat.st_size,
                "modified_utc": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
            }
        )
    return snapshot


def write_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def snapshot_to_map(entries: List[Dict[str, object]]) -> Dict[str, Dict[str, object]]:
    return {entry["path"]: entry for entry in entries}


def create_baseline() -> None:
    snapshot = collect_snapshot()
    payload = {
        "generated_at": utc_now(),
        "tracked_patterns": list(TRACKED_PATTERNS),
        "files": snapshot,
    }
    write_json(BASELINE_PATH, payload)
    print("Baseline written to", BASELINE_PATH)
    print("Tracked files:", len(snapshot))


def check_drift() -> int:
    if not BASELINE_PATH.exists():
        print("Baseline not found:", BASELINE_PATH)
        print("Run: python scripts/drift_check.py baseline")
        return 1

    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    current_files = collect_snapshot()

    baseline_map = snapshot_to_map(baseline.get("files", []))
    current_map = snapshot_to_map(current_files)

    added = sorted(path for path in current_map if path not in baseline_map)
    removed = sorted(path for path in baseline_map if path not in current_map)
    modified = sorted(
        path
        for path in current_map
        if path in baseline_map and current_map[path]["sha256"] != baseline_map[path]["sha256"]
    )

    report = {
        "checked_at": utc_now(),
        "baseline_path": BASELINE_PATH.relative_to(ROOT).as_posix(),
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "modified": len(modified),
            "drift_detected": bool(added or removed or modified),
        },
        "added": [current_map[path] for path in added],
        "removed": [baseline_map[path] for path in removed],
        "modified": [
            {
                "path": path,
                "baseline_sha256": baseline_map[path]["sha256"],
                "current_sha256": current_map[path]["sha256"],
                "baseline_size": baseline_map[path]["size"],
                "current_size": current_map[path]["size"],
            }
            for path in modified
        ],
    }
    write_json(REPORT_PATH, report)

    if report["summary"]["drift_detected"]:
        print("Drift detected.")
        print("Added:", len(added), "Removed:", len(removed), "Modified:", len(modified))
        print("Report written to", REPORT_PATH)
        return 2

    print("No drift detected.")
    print("Report written to", REPORT_PATH)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create and check configuration drift baselines.")
    parser.add_argument(
        "command",
        choices=("baseline", "check"),
        help="Create a baseline or compare the current workspace against the saved baseline.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "baseline":
        create_baseline()
        return 0
    return check_drift()


if __name__ == "__main__":
    raise SystemExit(main())
