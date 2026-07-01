# Lab Setup

This is how I built the environment Tripwire runs against. Nothing here is
sensitive, it's a throwaway lab I can rebuild. If you're reproducing it, expect a
couple of evenings of setup.

## Topology

Two VMs on a host-only / internal network so nothing touches the real world:

- **DC01** — Windows Server (Domain Controller for a test domain, e.g. `tripwire.local`)
- **WIN-CLIENT01** — Windows 10/11 client, domain-joined. This is the "compromised"
  workstation where I run the atomics.

A Splunk instance receives logs. I run Splunk Enterprise (free/dev licence) on a
separate box (or a Linux VM), with a Universal Forwarder on each Windows host.

## Logging (this is the part that actually matters)

Detections are only as good as the telemetry. I set up:

1. **Sysmon** on both Windows hosts, using a config derived from the
   SwiftOnSecurity / Olaf Hartong modular baselines. Key requirement for this repo:
   the config must **not** exclude `lsass.exe` from ProcessAccess (Event ID 10),
   or TRW-CRED-001 will never fire. Verify with a quick test dump before trusting it.
2. **Windows advanced audit policy** turned up so the Security log actually records:
   - 4720 (user account created) -> TRW-PERS-002
   - 4698 (scheduled task created) -> TRW-PERS-001
   - 1102 (audit log cleared) -> TRW-EVAS-001
   PowerShell script block logging (4104) is also worth enabling for depth.
3. **Splunk Universal Forwarder** shipping these channels into a `win` index:
   - `Microsoft-Windows-Sysmon/Operational`
   - `Security`
   - `System`
   - `Microsoft-Windows-PowerShell/Operational`

If your sourcetypes differ from `XmlWinEventLog:...`, adjust the SPL in each
detection to match your inputs. I standardised on XML event log input.

## Atomic Red Team

On WIN-CLIENT01, in an elevated PowerShell session:

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module Invoke-AtomicRedTeam
```

Then run the chain in `emulation/attack-chains/intrusion-chain.md`. Always run the
`-Cleanup` afterwards.

## Safety notes
- This lab intentionally runs offensive tooling. Keep it isolated from any network
  you care about. No bridged adapters.
- Some atomics (procdump on LSASS especially) will trip Defender. For lab work I run
  these on a host with real-time protection disabled, which is fine because the goal
  is generating telemetry, not evading EDR. In the write-up I'm explicit that a real
  attacker would face EDR here, and that's a limitation of the lab.

## What to screenshot for the repo
Capture these as `.webp` and drop them in `docs/screenshots/`:
- Each detection firing in Splunk (the search + results) — one per rule.
- The correlated view: all six on one host in time order.
- The validator passing locally and the green CI check on GitHub.
