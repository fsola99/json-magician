"""Build one CSV of tactics, techniques and sub-techniques across several MITRE ATT&CK releases."""

import argparse
import csv
import json
import os
import sys

# Tactic shortnames as they appear in `kill_chain_phases`, mapped to their TA identifier.
# Both the old and the new spelling are kept on purpose: the point of this script is to
# compare releases, and MITRE renamed "defense-evasion" to "stealth" (both TA0005) and
# later added "defense-impairment" (TA0112), so two releases name the same tactic
# differently.
TACTIC_IDS = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "stealth": "TA0005",
    "defense-impairment": "TA0112",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command-and-control": "TA0011",
    "impact": "TA0040",
}

UNKNOWN_TACTIC = "Unknown"

COLUMNS = [
    "Version",
    "Tactic",
    "TacticID",
    "Technique",
    "TechniqueID",
    "Subtechnique",
    "SubtechniqueID",
]


def tactic_id(shortname):
    """Return the TA identifier for a tactic shortname, or `Unknown` if it is not mapped."""
    return TACTIC_IDS.get(shortname, UNKNOWN_TACTIC)


def release_version(folder_name):
    """Return the ATT&CK version a release folder holds (`cti-ATT-CK-v14.1` gives `14.1`)."""
    if "-v" in folder_name:
        return folder_name.rsplit("-v", 1)[1]
    return folder_name


def read_technique(document, version):
    """Return the CSV rows for one ATT&CK attack-pattern document.

    Yields one row per tactic the technique belongs to. A technique with no tactics —
    which is how ATT&CK represents a revoked one — comes back as a single row whose
    tactic columns read `N/A`.
    """
    attack_pattern = document["objects"][0]
    attack_id = str(attack_pattern["external_references"][0]["external_id"])
    name = str(attack_pattern["name"])

    if "." in attack_id:
        # ATT&CK titles a sub-technique with its own name only, so the parent technique
        # column stays empty and the name goes in the sub-technique column.
        technique_id = attack_id.split(".")[0]
        technique_name = ""
        subtechnique_id = attack_id
        subtechnique_name = name
    else:
        technique_id = attack_id
        technique_name = name
        subtechnique_id = ""
        subtechnique_name = ""

    phases = attack_pattern.get("kill_chain_phases", [])
    if not phases:
        return [{
            "Version": version, "Tactic": "N/A", "TacticID": "N/A",
            "Technique": technique_name, "TechniqueID": technique_id,
            "Subtechnique": subtechnique_name, "SubtechniqueID": subtechnique_id,
        }]

    rows = []
    for phase in phases:
        tactic = str(phase["phase_name"])
        rows.append({
            "Version": version, "Tactic": tactic, "TacticID": tactic_id(tactic),
            "Technique": technique_name, "TechniqueID": technique_id,
            "Subtechnique": subtechnique_name, "SubtechniqueID": subtechnique_id,
        })
    return rows


def collect_rows(releases_dir):
    """Return the CSV rows for every release folder found under `releases_dir`.

    Folders without an `enterprise-attack/attack-pattern` subfolder are skipped with a
    warning, so a parent folder holding unrelated files still works.
    """
    rows = []

    for folder_name in sorted(os.listdir(releases_dir)):
        folder_path = os.path.join(releases_dir, folder_name)
        if not os.path.isdir(folder_path):
            continue

        patterns_path = os.path.join(folder_path, "enterprise-attack", "attack-pattern")
        if not os.path.isdir(patterns_path):
            print(f"[!] {folder_name}: no enterprise-attack/attack-pattern folder, skipping")
            continue

        version = release_version(folder_name)
        # Sorted so two runs produce byte-identical CSVs and a diff shows only real changes.
        file_names = sorted(f for f in os.listdir(patterns_path) if f.endswith(".json"))
        print(f"[+] {folder_name} (version {version}): {len(file_names)} files")

        for file_name in file_names:
            with open(os.path.join(patterns_path, file_name), "rb") as handle:
                document = json.load(handle)
            rows.extend(read_technique(document, version))

    return rows


def parse_args(argv=None):
    """Return the parsed command line."""
    parser = argparse.ArgumentParser(
        description=(
            "Build one CSV of tactics, techniques and sub-techniques across several "
            "MITRE ATT&CK releases, so they can be diffed."
        ),
        epilog=(
            "RELEASES is a folder holding one subfolder per release, each named after "
            "its version, for example MITRE/cti-ATT-CK-v14.1/enterprise-attack/. "
            "Download each release from https://github.com/mitre/cti as a ZIP."
        ),
    )
    parser.add_argument("releases", help="folder holding one subfolder per ATT&CK release")
    parser.add_argument(
        "-o", "--output", default="ttps.csv", help="CSV to write (default: %(default)s)"
    )
    return parser.parse_args(argv)


def main(argv=None):
    """Write the combined CSV and return the process exit code."""
    args = parse_args(argv)

    if not os.path.isdir(args.releases):
        print(f"[x] No such folder: {args.releases}")
        return 1

    rows = collect_rows(args.releases)
    if not rows:
        print("[x] No techniques found. Check that the folder layout matches the one in --help.")
        return 1

    with open(args.output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    unmapped = sorted({row["Tactic"] for row in rows if row["TacticID"] == UNKNOWN_TACTIC})
    if unmapped:
        print(f"[!] Tactics missing an ID (add them to TACTIC_IDS): {', '.join(unmapped)}")

    print(f"[+] Done: {len(rows)} rows in {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
