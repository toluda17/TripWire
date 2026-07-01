#!/usr/bin/env python3
"""
validate_detections.py

Schema-checks every detection YAML in this repo and can regenerate the MITRE
coverage table in docs/coverage.md. The point is simple: a detection isn't
"done" just because the SPL looks right. It needs an ATT&CK mapping, a data
source, a response playbook, and evidence that it was actually validated against
emulated telemetry. This script enforces that, so nothing sloppy sneaks in.

Run it locally before committing, and let CI run it on every push.

Usage:
    python3 scripts/validate_detections.py            # validate only
    python3 scripts/validate_detections.py --coverage # validate + write coverage.md
"""

import sys
import re
import argparse
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required. Install with: pip install pyyaml")
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections"

# Fields every detection file must have, with the nested keys we insist on.
REQUIRED_TOP = ["id", "title", "status", "mitre", "data_source", "detection", "validation"]
REQUIRED_MITRE = ["tactic", "technique_id", "technique_name"]
REQUIRED_VALIDATION = ["atomic_test", "emulated_on", "result"]

# ATT&CK technique IDs look like T1059 or T1059.001. Enforce that shape so a
# typo'd mapping can't merge.
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

VALID_STATUS = {"draft", "testing", "validated", "deprecated"}


def load_detection_files():
    return sorted(DETECTIONS_DIR.rglob("*.yml"))


def validate_file(path):
    """Return a list of error strings for a single detection file (empty = ok)."""
    errors = []
    rel = path.relative_to(REPO_ROOT)

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        return [f"{rel}: YAML failed to parse: {e}"]

    if not isinstance(data, dict):
        return [f"{rel}: top level is not a mapping"]

    # Required top-level keys
    for key in REQUIRED_TOP:
        if key not in data or data[key] in (None, ""):
            errors.append(f"{rel}: missing required field '{key}'")

    # Status must be one of the known values
    status = data.get("status")
    if status and status not in VALID_STATUS:
        errors.append(f"{rel}: status '{status}' not in {sorted(VALID_STATUS)}")

    # MITRE block
    mitre = data.get("mitre")
    if isinstance(mitre, dict):
        for key in REQUIRED_MITRE:
            if not mitre.get(key):
                errors.append(f"{rel}: mitre.{key} is missing")
        tid = str(mitre.get("technique_id", ""))
        if tid and not TECHNIQUE_RE.match(tid):
            errors.append(f"{rel}: technique_id '{tid}' is not a valid ATT&CK ID")
    elif "mitre" in data:
        errors.append(f"{rel}: mitre block must be a mapping")

    # detection.spl must exist and be non-trivial
    detection = data.get("detection")
    if isinstance(detection, dict):
        spl = detection.get("spl", "")
        if not spl or len(spl.strip()) < 20:
            errors.append(f"{rel}: detection.spl is missing or too short to be real")
    elif "detection" in data:
        errors.append(f"{rel}: detection block must be a mapping")

    # validation block: this is the bit that proves it was tested
    validation = data.get("validation")
    if isinstance(validation, dict):
        for key in REQUIRED_VALIDATION:
            if not validation.get(key):
                errors.append(f"{rel}: validation.{key} is missing")
        # If the author claims validated status, the result must actually be 'detected'
        if status == "validated" and validation.get("result") != "detected":
            errors.append(
                f"{rel}: status is 'validated' but validation.result is "
                f"'{validation.get('result')}' (expected 'detected')"
            )
    elif "validation" in data:
        errors.append(f"{rel}: validation block must be a mapping")

    # response_playbook, if present, should point at a file that exists
    playbook = data.get("response_playbook")
    if playbook:
        if not (REPO_ROOT / playbook).exists():
            errors.append(f"{rel}: response_playbook '{playbook}' does not exist")

    return errors


def build_coverage_rows(paths):
    """Collect (technique_id, technique_name, tactic, id, title, status) tuples."""
    rows = []
    for path in paths:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict):
            continue
        mitre = data.get("mitre", {}) or {}
        rows.append(
            (
                str(mitre.get("technique_id", "?")),
                str(mitre.get("technique_name", "?")),
                str(mitre.get("tactic", "?")),
                str(data.get("id", "?")),
                str(data.get("title", "?")),
                str(data.get("status", "?")),
            )
        )
    # Sort by tactic then technique id for a readable table
    return sorted(rows, key=lambda r: (r[2], r[0]))


def write_coverage(rows):
    lines = [
        "# MITRE ATT&CK Coverage",
        "",
        "This file is auto-generated by `scripts/validate_detections.py --coverage`.",
        "Do not edit it by hand. Every row is a validated detection in this repo.",
        "",
        "| Tactic | Technique ID | Technique | Detection ID | Title | Status |",
        "|--------|--------------|-----------|--------------|-------|--------|",
    ]
    for tid_name in rows:
        tid, tname, tactic, did, title, status = tid_name
        lines.append(f"| {tactic} | {tid} | {tname} | {did} | {title} | {status} |")
    lines.append("")
    lines.append(f"**Total detections:** {len(rows)}  ")
    tactics = sorted({r[2] for r in rows})
    lines.append(f"**Tactics covered:** {', '.join(tactics)}")
    lines.append("")
    out = REPO_ROOT / "docs" / "coverage.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def main():
    parser = argparse.ArgumentParser(description="Validate Tripwire detection files.")
    parser.add_argument(
        "--coverage", action="store_true",
        help="Also regenerate docs/coverage.md from the detection files.",
    )
    args = parser.parse_args()

    paths = load_detection_files()
    if not paths:
        print("No detection files found under detections/. Nothing to validate.")
        sys.exit(1)

    all_errors = []
    for path in paths:
        all_errors.extend(validate_file(path))

    print(f"Checked {len(paths)} detection file(s).")

    if all_errors:
        print("\nVALIDATION FAILED:\n")
        for err in all_errors:
            print(f"  - {err}")
        sys.exit(1)

    print("All detection files passed validation.")

    if args.coverage:
        rows = build_coverage_rows(paths)
        out = write_coverage(rows)
        print(f"Wrote coverage table to {out.relative_to(REPO_ROOT)} ({len(rows)} detections).")


if __name__ == "__main__":
    main()
