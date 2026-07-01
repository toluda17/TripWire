# Tripwire

This is a detection engineering lab where I run real attack techniques against a small Windows
and Active Directory lab using Atomic Red Team, then write Splunk detections against
the telemetry those attacks actually generate. The point is to learn how detections
get made from the log up, rather than copying rules I can't explain.

Status: everything in the repo is written, but I'm still building the lab and running
the chain for real. Please check the bottom for the full status.

---

## What's here

Six Splunk detections, one per step of a single attack chain, each mapped to a MITRE
ATT&CK technique. They live in `detections/`, sorted by tactic, as YAML files with
the SPL and metadata in one place.

The attack chain is in `emulation/`, built from Atomic Red Team tests so it runs as
one intrusion rather than six unrelated techniques.

An incident response runbook in `runbooks/` covers the whole chain: triage,
containment, and evidence to collect. I wanted the project to go past "an alert
fired" into what you actually do about it.

A small Python validator in `scripts/`, with a GitHub Actions workflow that runs it
on every push. It checks each detection is mapped and filled out, and regenerates
the coverage table.

---

## The attack chain

One intrusion, start to finish, with a detection for every step:

| Step | Technique | ATT&CK ID | Detection |
|------|-----------|-----------|-----------|
| 1 | Encoded PowerShell execution | T1059.001 | TRW-EXEC-001 |
| 2 | Domain account discovery | T1087.002 | TRW-DISC-001 |
| 3 | Scheduled task persistence | T1053.005 | TRW-PERS-001 |
| 4 | Local account creation | T1136.001 | TRW-PERS-002 |
| 5 | LSASS credential dumping | T1003.001 | TRW-CRED-001 |
| 6 | Clear Windows event logs | T1070.001 | TRW-EVAS-001 |

Get a foothold, look around, dig in so you survive a reboot, steal credentials, wipe
the logs on the way out. Step-by-step commands are in
`emulation/attack-chains/intrusion-chain.md`.

---

## How a detection is put together

Each detection is a YAML file rather than a saved search in Splunk, so it can be
reviewed and diffed like code and carry everything in one place: the ATT&CK mapping,
data source, SPL, expected false positives, a link to the runbook, and whether it's
been tested. Same idea as Sigma. Rough shape:

```yaml
id: TRW-CRED-001
mitre:
  technique_id: T1003.001
data_source:
  log_source: Sysmon
  event_id: 10
detection:
  spl: >
    ... EventCode=10 TargetImage="*\lsass.exe" (GrantedAccess="0x1010" OR ...)
validation:
  atomic_test: emulation/attack-chains/intrusion-chain.md#step-5
  result: detected
```

A file can't claim `status: validated` unless its result is `detected`, so I can't
mark something proven when it isn't. The validator enforces that.

---

## Frameworks

**MITRE ATT&CK.** Every detection maps to a technique ID (see the table, and the full
list in `docs/coverage.md`). The chain covers five tactics: Execution, Discovery,
Persistence, Credential Access, Defense Evasion.

**NIST CSF.** Mostly Detect and Respond. Detect is the detections themselves,
continuous monitoring of the logs (DE.CM) with each rule documenting its data source
and false positives (DE.AE). Respond is the runbook (RS.AN, RS.MI, RS.CO). I've left
Protect and Recover out because a detection lab doesn't really show them.

---

## Setup and running

The lab is two Windows VMs plus Sysmon, Splunk and Atomic Red Team. Full build in
`docs/lab-setup.md`. Once it's up, run the chain from the client:

```powershell
# elevated PowerShell on the compromised workstation
Invoke-AtomicTest T1059.001 -TestNumbers 1   # then the rest of the chain
```

Check the detection files and rebuild the coverage table:

```bash
python3 scripts/validate_detections.py --coverage
```

---

## Limitations

Please keep in mind that this is still just a lab lol. A real attacker would be up against EDR, and some of these (the LSASS one
especially) would look different or get blocked under a real endpoint product. Mine's
turned off so I can generate the telemetry.

The detections are tuned for a quiet lab. In a noisy network they'd need the
allowlisting each rule describes before they'd be usable. And six techniques is a
slice, not coverage.

---

## Status

Written: all six detections, the emulation chain, the runbook, the validator and CI.

Still to do: build the lab, run the chain, confirm each detection fires, add the
screenshots to `docs/screenshots/`, and flip the statuses from testing to validated.
