import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "artifacts" / "sbom"

SERVICES = {
    "agent": {
        "image": "mcp-security-poc-agent:latest",
        "dockerfile": ROOT / "agent" / "dockerfile",
        "paths": [ROOT / "agent"],
        "pip_command": ["python", "-m", "pip", "list", "--format=json"],
    },
    "mcp-server": {
        "image": "mcp-security-poc-mcp-server:latest",
        "dockerfile": ROOT / "mcp-server" / "dockerfile",
        "paths": [ROOT / "mcp-server"],
        "pip_command": ["python", "-m", "pip", "list", "--format=json"],
    },
    "proxy": {
        "image": "mcp-security-poc-proxy:latest",
        "dockerfile": ROOT / "proxy" / "dockerfile",
        "paths": [ROOT / "proxy"],
        "pip_command": None,
    },
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_command(command: List[str]) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def safe_run_json(command: List[str]) -> Optional[object]:
    try:
        return json.loads(run_command(command))
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return None


def parse_base_image(dockerfile_path: Path) -> str:
    for line in dockerfile_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            return stripped.split()[1]
    return "unknown"


def collect_file_components(paths: List[Path]) -> List[Dict[str, object]]:
    components = []
    for base in paths:
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix == ".pyc":
                continue
            relative_path = path.relative_to(ROOT).as_posix()
            components.append(
                {
                    "type": "file",
                    "name": relative_path,
                    "properties": [
                        {"name": "size", "value": str(path.stat().st_size)},
                    ],
                }
            )
    return components


def collect_python_components(image: str, pip_command: Optional[List[str]]) -> List[Dict[str, object]]:
    if not pip_command:
        return []

    command = ["docker", "run", "--rm", image] + pip_command
    packages = safe_run_json(command)
    if not isinstance(packages, list):
        return []

    components = []
    for package in packages:
        name = package.get("name")
        version = package.get("version")
        if not name or not version:
            continue
        components.append(
            {
                "type": "library",
                "name": str(name),
                "version": str(version),
                "purl": "pkg:pypi/{name}@{version}".format(name=name, version=version),
            }
        )
    return components


def inspect_image(image: str) -> Dict[str, object]:
    data = safe_run_json(["docker", "image", "inspect", image])
    if isinstance(data, list) and data:
        details = data[0]
        return {
            "id": details.get("Id"),
            "created": details.get("Created"),
            "repo_tags": details.get("RepoTags", []),
            "os": details.get("Os"),
            "architecture": details.get("Architecture"),
        }
    return {
        "id": None,
        "created": None,
        "repo_tags": [image],
        "os": None,
        "architecture": None,
    }


def build_sbom(service_name: str, service_config: Dict[str, object]) -> Dict[str, object]:
    image = str(service_config["image"])
    dockerfile_path = Path(service_config["dockerfile"])
    paths = [Path(path) for path in service_config["paths"]]
    pip_command = service_config.get("pip_command")

    metadata = inspect_image(image)
    components = [
        {
            "type": "container",
            "name": image,
            "version": "latest",
            "properties": [
                {"name": "base_image", "value": parse_base_image(dockerfile_path)},
                {"name": "image_id", "value": str(metadata.get("id"))},
            ],
        }
    ]
    components.extend(collect_python_components(image, pip_command))
    components.extend(collect_file_components(paths))

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:{name}-{timestamp}".format(
            name=service_name, timestamp=utc_now().replace(":", "").replace("-", "")
        ),
        "version": 1,
        "metadata": {
            "timestamp": utc_now(),
            "component": {
                "type": "application",
                "name": service_name,
                "version": "latest",
            },
            "properties": [
                {"name": "image", "value": image},
                {"name": "base_image", "value": parse_base_image(dockerfile_path)},
                {"name": "image_created", "value": str(metadata.get("created"))},
                {"name": "os", "value": str(metadata.get("os"))},
                {"name": "architecture", "value": str(metadata.get("architecture"))},
            ],
        },
        "components": components,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate simple CycloneDX-style SBOM files.")
    parser.add_argument(
        "--service",
        choices=sorted(SERVICES.keys()),
        help="Generate SBOM for a single service. Default is all services.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    targets = [args.service] if args.service else sorted(SERVICES.keys())
    for service_name in targets:
        payload = build_sbom(service_name, SERVICES[service_name])
        output_path = OUTPUT_DIR / "{name}.sbom.json".format(name=service_name)
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print("SBOM written to", output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
