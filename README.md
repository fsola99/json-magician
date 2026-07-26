# json-magician

Builds a single CSV of tactics, techniques and sub-techniques across **several
MITRE ATT&CK releases at once**, so you can diff them.

ATT&CK is not static: techniques get added, revoked, split into sub-techniques, and
tactics occasionally get renamed. If your detection coverage is mapped to technique
IDs, every ATT&CK release is a question — *what moved, and does our mapping still
hold?* This answers it as a spreadsheet you can pivot.

## Usage

```bash
python json-magicianv2.py <parent_folder> [output.csv]
```

The parent folder holds one subfolder per release, each named with its version:

```
MITRE/
  cti-ATT-CK-v13.1/enterprise-attack/attack-pattern/*.json
  cti-ATT-CK-v14.1/enterprise-attack/attack-pattern/*.json
```

Each release comes from [mitre/cti](https://github.com/mitre/cti) — pick the tag you
want and download it as a ZIP. Output defaults to `ttps.csv`.

## Output

One row per technique/tactic pair, since a technique can belong to several tactics:

| Version | Tactica | TacticaID | Tecnica | TecnicaID | Subtecnica | SubtecnicaID |
|---|---|---|---|---|---|---|
| 14.1 | persistence | TA0003 | | T1053 | Scheduled Task | T1053.005 |
| 14.1 | stealth | TA0005 | Indicator Removal from Tools | T1066 | | |

Revoked techniques carry no tactics and come through as `N/A` — which is exactly what
you want to see when diffing releases.

## On tactic names

The tactic lookup deliberately holds both old and new names. MITRE renamed
`defense-evasion` to `stealth` (both TA0005) and later added `defense-impairment`
(TA0112), so an old release and a new one call the same tactic different things. A
tool whose entire job is comparing releases has to understand both.

Anything not in the lookup is marked `Unknown` and reported at the end of the run, so
a future rename surfaces immediately instead of silently corrupting a column.

## Related

Part of a small set of ATT&CK utilities:

- [ttps-magician](https://github.com/fsola99/ttps-magician) — exports the full technique catalogue
- [groups-magician](https://github.com/fsola99/groups-magician) — maps threat groups to their techniques
- [ioc-hunter](https://github.com/fsola99/ioc-hunter) — IoC triage console with a browsable ATT&CK matrix
