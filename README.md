# Tripwire

An adversary emulation and detection engineering lab. I run real attack techniques
against a Windows/Active Directory lab using Atomic Red Team, generate actual
telemetry from those executions, then write and validate Splunk detections against
that real data. Not synthetic examples, not copied rules I can't explain: every
detection here fired against telemetry I generated myself, and I can talk through
each one.

I built this to get hands-on with the detection engineering lifecycle end to end:
emulate a technique, see what it looks like in the logs, write a detection, prove it
fires, and document how I'd respond when it does. It sits alongside my cloud attack
simulation project (CloudSweeper): that one covers AWS, this one covers endpoint and
Active Directory.

## What's in here

- **Six validated Splunk detections**, each mapped to a MITRE ATT&CK technique and
  each tested against emulated telemetry. They live in `detections/`, organised by
  tactic, as structured YAML with the SPL inside.
- **A scripted intrusion chain** (`emulation/`) built from Atomic Red Team tests that
  runs as one coherent attack story from foothold to anti-forensics.
- **An incident response runbook** (`runbooks/`) covering triage, containment, and
  evidence collection for the full chain, so the project goes detection-to-response,
  not just detection-to-alert.
- **A validator + CI** (`scripts/`, `.github/`) that schema-checks every detection
  and auto-generates the coverage table, so nothing unmapped or untested merges.

## The attack chain

I emulate one realistic intrusion and detect every step of it:

| Step | Technique | ATT&CK ID | Detection |
|------|-----------|-----------|-----------|
| 1 | Encoded PowerShell execution | T1059.001 | TRW-EXEC-001 |
| 2 | Domain account discovery | T1087.002 | TRW-DISC-001 |
| 3 | Scheduled task persistence | T1053.005 | TRW-PERS-001 |
| 4 | Local account creation | T1136.001 | TRW-PERS-002 |
| 5 | LSASS credential dumping | T1003.001 | TRW-CRED-001 |
| 6 | Clear Windows event logs | T1070.001 | TRW-EVAS-001 |

Full step-by-step is in `emulation/attack-chains/intrusion-chain.md`. The
auto-generated coverage table is in `docs/coverage.md`.

## How a detection is structured

Each detection is a YAML file so it's reviewable, diffable, and machine-checkable
(the same idea as Sigma). Every file carries its ATT&CK mapping, its data source,
the SPL, known false positives, a link to the response runbook, and validation
evidence proving it actually fired. Example fields:

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

A detection can't claim `status: validated` unless its recorded result is
`detected`. The validator enforces that.

## Framework alignment

### MITRE ATT&CK
Every detection maps explicitly to a technique ID (see the table above and
`docs/coverage.md`). The chain spans five tactics: Execution, Discovery,
Persistence, Credential Access, and Defense Evasion.

### NIST CSF
This project mostly demonstrates the **Detect** and **Respond** functions.

- **Detect (DE).** The detections are continuous security monitoring
  (DE.CM): I generate adversary telemetry and alert on it. Each rule documents its
  data source and expected false positives, which is the analysis side of detection
  (DE.AE, understanding what a detected event actually means).
- **Respond (RS).** The runbook covers response analysis, mitigation, and
  communications (RS.AN, RS.MI, RS.CO): how to triage an alert, contain the host and
  accounts, collect evidence in order of volatility, and hand off.
- **Identify (ID), lightly.** Choosing which techniques to emulate is a small risk
  assessment: I picked a chain that reflects common real-world intrusion behaviour
  rather than random atomics.

The project deliberately stops short of claiming Protect and Recover coverage,
because a detection lab doesn't meaningfully demonstrate those, and I'd rather scope
honestly than overclaim.

## Running it

Lab build (two Windows VMs, Sysmon, Splunk, Atomic Red Team) is documented in
`docs/lab-setup.md`. Once the lab is up:

```powershell
# On the compromised workstation, elevated PowerShell
Invoke-AtomicTest T1059.001 -TestNumbers 1   # and so on through the chain
```

Then validate the detection files and regenerate the coverage table:

```bash
python3 scripts/validate_detections.py --coverage
```

## Limitations (being honest)

- It's a lab. A real attacker would be facing EDR, and some of these techniques
  (LSASS access especially) would look different under an EDR that blocks or alters
  the behaviour. I call this out rather than pretending the lab is production.
- The detections are tuned for my lab's sourcetypes and a fairly clean baseline. In a
  noisy real environment they'd need the allowlisting each rule's `false_positives`
  section describes.
- Six techniques is a slice, not full coverage. It's a coherent slice chosen to tell
  one story well.

## About

Built by Toluwani Ashiru, second-year Computing Science student at the University of
Glasgow, holder of CySA+, and a DEATHCon scholarship attendee. I wanted a project I
could speak to line by line in an interview for a SOC analyst or detection
engineering role, and this is it.
