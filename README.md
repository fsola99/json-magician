# json-magician

Builds a single CSV of tactics, techniques and sub-techniques across **several
MITRE ATT&CK releases at once**, so you can diff them.

ATT&CK is not static: techniques get added, revoked, split into sub-techniques, and
tactics occasionally get renamed. If your detection coverage is mapped to technique
IDs, every ATT&CK release is a question — *what moved, and does our mapping still
hold?* This answers it as a spreadsheet you can pivot.

Standard library only — nothing to install.

## What you need to give it

One folder holding **one subfolder per ATT&CK release**, each named after its version:

```
MITRE/
  cti-ATT-CK-v13.1/enterprise-attack/attack-pattern/*.json
  cti-ATT-CK-v14.1/enterprise-attack/attack-pattern/*.json
```

Each release comes from [mitre/cti](https://github.com/mitre/cti): pick the tag you
want and download it as a ZIP, then unpack it into the parent folder. The version is
read from whatever follows `-v` in the folder name, so the ZIP's own name works
unchanged. Subfolders without an `enterprise-attack/attack-pattern` inside are skipped
with a warning, so unrelated files in the parent folder are harmless.

## Usage

```bash
python json-magician.py MITRE/                  # writes ttps.csv
python json-magician.py MITRE/ -o compare.csv
```

| Argument | Default | What it does |
|---|---|---|
| `releases` | *(required)* | Folder holding one subfolder per ATT&CK release. |
| `-o`, `--output` | `ttps.csv` | CSV to write. |

Rows come out in a stable order, so two runs give byte-identical files and a diff
shows only real changes.

## Output

One row per technique and tactic pair, since a technique can belong to several tactics:

| Version | Tactic | TacticID | Technique | TechniqueID | Subtechnique | SubtechniqueID |
|---|---|---|---|---|---|---|
| 13.1 | execution | TA0002 | | T1059 | PowerShell | T1059.001 |
| 13.1 | defense-evasion | TA0005 | Indicator Removal from Tools | T1066 | | |
| 18.0 | stealth | TA0005 | | T1059 | PowerShell | T1059.001 |

Revoked techniques carry no tactics and come through as `N/A` — which is exactly what
you want to see when diffing releases.

## On tactic names

The tactic lookup deliberately holds both old and new names. MITRE renamed
`defense-evasion` to `stealth` (both TA0005) and later added `defense-impairment`
(TA0112), so an old release and a new one call the same tactic different things. A
tool whose entire job is comparing releases has to understand both — the third row
above is the same technique as the first, two releases apart.

Anything not in the lookup is marked `Unknown` and reported at the end of the run, so
a future rename surfaces immediately instead of silently corrupting a column.

## The other magicians

Small, standalone tools that each answer one question:

- [ttps-magician](https://github.com/fsola99/ttps-magician) — what is every ATT&CK technique, as a spreadsheet?
- [groups-magician](https://github.com/fsola99/groups-magician) — which techniques does a given threat group use?
- [hash-magician-reloaded](https://github.com/fsola99/hash-magician-reloaded) — what are the hashes of every file in this folder?
- [Hash-Magician](https://github.com/fsola99/Hash-Magician) — the same, on PySimpleGUI

And the larger project they feed into:

- [ioc-hunter](https://github.com/fsola99/ioc-hunter) — triage console for hashes, IPs, domains and URLs, with a browsable ATT&CK matrix
