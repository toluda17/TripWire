# Runbook RB-001: PowerShell-Initiated Intrusion Chain

## When to use this
You are here because one or more of these detections fired from the same host,
ideally clustered in time:

| Alert | Technique | What it means |
|-------|-----------|---------------|
| TRW-EXEC-001 | T1059.001 | Encoded PowerShell ran (foothold) |
| TRW-DISC-001 | T1087.002 | Domain accounts were enumerated |
| TRW-PERS-001 | T1053.005 | A scheduled task was created |
| TRW-PERS-002 | T1136.001 | A local account was created |
| TRW-CRED-001 | T1003.001 | LSASS was accessed (credential dumping) |
| TRW-EVAS-001 | T1070.001 | Event logs were cleared |

Treat any TRW-CRED-001 (LSASS) or TRW-EVAS-001 (log clearing) hit as high severity
on its own. Treat three or more of these from one host as a probable active
intrusion and escalate immediately.

This runbook maps to NIST CSF **Respond (RS)**: Analysis, Mitigation, and
Communications.

---

## 1. Triage (confirm it's real, set severity)

Goal: decide in a few minutes whether this is a true positive and how bad it is.

1. **Pull the host's timeline.** In Splunk, pivot on the host and widen to the last
   24 hours:
   ```
   index=win host=<HOST> | sort _time | table _time EventCode Image CommandLine User
   ```
   You are looking for the chain in sequence. Sequence raises confidence.
2. **Identify the account(s).** Which user launched the encoded PowerShell? Is it a
   normal user, a service account, or an admin? An admin account behaving this way is
   worse (more blast radius).
3. **Check the parent process** of the encoded PowerShell (ParentImage). A browser,
   Office app, or Outlook as the parent suggests phishing-driven execution.
4. **Rule out sanctioned activity.** Confirm there is no change ticket, pentest, or
   deployment window that explains it. Check the allowlists referenced in each
   detection's `false_positives`.
5. **Set severity.** LSASS access or log clearing present, or admin account involved,
   or three-plus alerts: **High, escalate now.** Otherwise Medium, keep investigating.

Evidence to capture at this stage: the Splunk timeline export, the specific alert
events (with _time, host, user, CommandLine), and the parent-process context.

---

## 2. Containment (stop it spreading)

Order matters: preserve volatile evidence *before* you pull the plug where you can.

1. **Isolate the host from the network.** Prefer EDR network-contain (keeps the
   machine up so you can still collect memory) over yanking the cable. If no EDR,
   disable the switch port or move to a quarantine VLAN.
2. **Do NOT immediately power off.** Powering off destroys memory-resident evidence
   (the very LSASS content you care about). Isolate first, image later.
3. **Disable compromised accounts.** Disable (don't delete) the account that ran the
   PowerShell and any local account that TRW-PERS-002 flagged as newly created.
   Deleting destroys evidence; disabling stops use.
4. **Force credential reset for exposed identities.** If TRW-CRED-001 fired, assume
   every credential cached on that host is compromised. Reset those users and any
   privileged accounts that had logged into the host recently. If a domain admin was
   exposed, this becomes a domain-wide incident: reset krbtgt (twice) per your IR plan.
5. **Neutralise persistence.** Disable the scheduled task from TRW-PERS-001 (note its
   name and action first, that's evidence).

---

## 3. Evidence to collect (for investigation and handover)

Collect in rough order of volatility, most volatile first:

- **Memory image** of the host, if capability exists, before shutdown.
- **The raw events**, exported from Splunk (they may have been cleared locally by
  TRW-EVAS-001, which is exactly why forwarding off-host matters).
- **Sysmon EID 1** process-creation records for the full chain: command lines,
  hashes, parent processes.
- **The decoded PowerShell payload** (Base64-decode the CommandLine from TRW-EXEC-001).
- **The scheduled task definition** (export the task XML).
- **The new local account details** (name, groups, creation time from event 4720).
- **LSASS access details**: SourceImage and CallTrace from the Sysmon EID 10 event.
- **A written timeline** with UTC timestamps of each observed action.

Preserve integrity: hash your collected files (SHA-256) and record who collected
what, when. This is the chain-of-custody habit interviewers like to hear about.

---

## 4. Eradication and recovery (brief)

- Remove persistence (task + account), confirm no other persistence was added.
- Rebuild the host from a known-good image rather than trusting a cleaned box,
  especially after credential dumping.
- Restore affected accounts with fresh credentials and MFA.
- Only return the host to the network once you're confident it's clean.

---

## 5. Communications and lessons learned

- Notify the incident owner and, if a privileged account or domain-wide credential
  exposure occurred, whoever owns your major-incident process.
- After closure, write up: what fired, what was true, what the detections missed,
  and one improvement to the detections or the logging. Feeding this back is the
  "detection engineering lifecycle" and it's a strong note to end an interview story
  on.
