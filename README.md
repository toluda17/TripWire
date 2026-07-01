# Tripwire

This is a detection engineering lab I'm building to learn how detections actually
get made: run a real attack technique, look at what it leaves behind in the logs,
write a Splunk detection for it, and check the detection really fires. I'm using
Atomic Red Team to run the techniques against a small Windows and Active Directory
lab, so the telemetry is real rather than something I made up to fit a rule I'd
already written.

It's a companion to CloudSweeper, my AWS attack simulation project. That one lives
in the cloud, this one lives on the endpoint and in AD. Between them I wanted to
cover both sides, because the internships I'm aiming at ask about both.

Heads up on status: the repo structure, the detections, the runbook and the
validator are all written, but I'm still standing up the lab and running the chain
for real. Until I've done that and added the screenshots, treat the detections as
drafted-and-ready-to-test, not battle-tested. I'd rather say that than pretend I've
run something I haven't. See the status note at the bottom.

## What's here

Six Splunk detections, one per step of a single attack chain, each mapped to a
MITRE ATT&CK technique. They live in `detections/`, sorted by tactic. Each one is a
YAML file with the SPL inside it plus the metadata that makes it reviewable.

The attack chain itself is in `emulation/`. It's built from Atomic Red Team tests
and it runs as one story rather than six unrelated techniques.

There's an incident response runbook in `runbooks/` for the whole chain: how I'd
triage the alerts, contain the host, and collect evidence. I wanted the project to
go past "an alert fired" into "here's what you do about it," because that's the part
that actually matters in a SOC.

And there's a small Python validator in `scripts/` with a GitHub Actions workflow
that runs it on every push. It checks each detection is properly mapped and filled
out, and it regenerates the coverage table. More on why below.

## The attack chain

One intrusion, start to finish, and a detection for every step:

| Step | Technique | ATT&CK ID | Detection |
|------|-----------|-----------|-----------|
| 1 | Encoded PowerShell execution | T1059.001 | TRW-EXEC-001 |
| 2 | Domain account discovery | T1087.002 | TRW-DISC-001 |
| 3 | Scheduled task persistence | T1053.005 | TRW-PERS-001 |
| 4 | Local account creation | T1136.001 | TRW-PERS-002 |
| 5 | LSASS credential dumping | T1003.001 | TRW-CRED-001 |
| 6 | Clear Windows event logs | T1070.001 | TRW-EVAS-001 |

The idea is a made-up but realistic break-in: get a foothold, look around, dig in so
you survive a reboot, steal some credentials, then wipe the logs on the way out. The
step-by-step commands are in `emulation/attack-chains/intrusion-chain.md`.

Running these in order matters. Six alerts from one machine in a few minutes is a
much louder signal than any one of them alone, and eventually I want a correlation
search that raises a single high-priority incident when a few of these fire
together, instead of six separate alerts nobody has time to read.

## How a detection is put together

I wrote each detection as a YAML file instead of just saving a search in Splunk. The
reason is that a file can be reviewed and diffed like code, and it can carry
everything that matters about the detection in one place: the ATT&CK mapping, the
data source, the SPL, the false positives I expect, a link to the runbook, and a
record of whether it's actually been tested. This is the same idea as Sigma. Rough
shape of a file:

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

The validator won't let a file say it's `validated` unless its recorded result is
actually `detected`, so I can't accidentally claim a detection works when I haven't
proven it. That guard is the whole reason the validator exists.

## Frameworks

### MITRE ATT&CK
Every detection points at a specific technique ID (the table above, and the full
list in `docs/coverage.md`, which the validator generates). The chain touches five
tactics: Execution, Discovery, Persistence, Credential Access and Defense Evasion.

### NIST CSF
This is mostly a Detect and Respond project, and I've tried to be honest about which
bits it actually shows rather than name-dropping all five functions.

Detect is the core of it. The detections are continuous monitoring of the logs
(DE.CM), and because each rule writes down its data source and its likely false
positives, there's a bit of the "understanding what an alert means" side too
(DE.AE).

Respond is the runbook: triage, containment, evidence collection, handover (RS.AN,
RS.MI, RS.CO).

There's a little bit of Identify in the sense that picking which six techniques to
emulate is a small risk decision, I went for a chain that looks like a real
intrusion rather than a random grab-bag.

I've deliberately not claimed Protect or Recover. A detection lab doesn't really
demonstrate those, and I'd rather scope it honestly than pad the list.

## Running it

The lab is two Windows VMs plus Sysmon, Splunk and Atomic Red Team. The full build
is in `docs/lab-setup.md`. Once it's up, you run the chain from the client:

```powershell
# elevated PowerShell on the compromised workstation
Invoke-AtomicTest T1059.001 -TestNumbers 1   # then the rest of the chain
```

And to check the detection files and rebuild the coverage table:

```bash
python3 scripts/validate_detections.py --coverage
```

## Where it falls short

It's a lab, so I want to be straight about the limits. A real attacker here would be
up against EDR, and some of these techniques (the LSASS one especially) would look
different or get blocked outright under a proper endpoint product. My lab has that
turned off so I can actually generate the telemetry, which is fine for learning but
isn't the real world.

The detections are also tuned for my lab, which is quiet and clean. Drop them into a
noisy real network and they'd need the allowlisting each rule describes in its
false_positives section before they'd be usable.

And six techniques is a slice, not coverage. I picked a slice that tells one story
well rather than trying to do everything badly.

## Status

Written and ready to test:
- all six detection files, mapped and filled out
- the emulation chain
- the runbook
- the validator and CI

Still to do:
- build the lab and run the chain for real
- confirm each detection fires and capture screenshots into `docs/screenshots/`
- flip the detection status from testing to validated once I've seen them fire

## About me

I'm Toluwani Ashiru, a second-year Computing Science student at Glasgow. I've got
CySA+ and went to DEATHCon on a scholarship. I built this because I wanted a project
I could sit in an interview and explain properly, every file, not just point at a
repo and hope nobody asks how it works.
