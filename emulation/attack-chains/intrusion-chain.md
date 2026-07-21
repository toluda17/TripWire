# Intrusion Chain: Foothold to Anti-Forensics

This is the scripted attack narrative Tripwire emulates. Each step runs a real
Atomic Red Team test against the lab, generates real telemetry, and maps to one
detection in this repo. I run these in order so the resulting logs tell a single
coherent story, which is what I validate the detections against.

I run every test with Invoke-AtomicRedTeam from an elevated PowerShell session on
the compromised workstation (WIN-CLIENT01), unless a step says otherwise. I always
run the `-Cleanup` afterwards so the lab returns to a known state.

## Prerequisites
- Atomic Red Team + Invoke-AtomicRedTeam installed (see docs/lab-setup.md)
- Sysmon running with the SwiftOnSecurity-derived config in docs/
- Splunk Universal Forwarder shipping the four channels to the `win` index

## The chain

### Step 1 — Encoded PowerShell execution (T1059.001)
Detection: TRW-EXEC-001
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1
```
Simulates initial code execution via an obfuscated (Base64-encoded) PowerShell
command (This is the foothold). 

### Step 2 — Domain account discovery (T1087.002)
Detection: TRW-DISC-001
```powershell
Invoke-AtomicTest T1087.002 -TestNumbers 1
```
The attacker orients: who are the domain admins, what accounts exist etc.

### Step 3 — Scheduled task persistence (T1053.005)
Detection: TRW-PERS-001
```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
```
Attacker establishes reboot-surviving persistence.

### Step 4 — Local account creation (T1136.001)
Detection: TRW-PERS-002
```powershell
Invoke-AtomicTest T1136.001 -TestNumbers 1
```
A second, quieter way back in (persistence lol).

### Step 5 — LSASS credential dumping (T1003.001)
Detection: TRW-CRED-001
```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 3
```
Attacker harvests credentials from LSASS to move laterally. This is the highest
severity step: from here they can become other users.

### Step 6 — Clear event logs (T1070.001)
Detection: TRW-EVAS-001
```powershell
Invoke-AtomicTest T1070.001 -TestNumbers 2
```
Anti-forensics: destroy the evidence trail on the host.

## Cleanup
```powershell
Invoke-AtomicTest T1059.001,T1087.002,T1053.005,T1136.001,T1003.001,T1070.001 -Cleanup
```

## Why this order matters for detection engineering
Running the chain in sequence lets me test not just individual rules but the
correlation story: six alerts on one host inside a few minutes is a far stronger
signal than any single alert. In a real SIEM I would build a correlation search
that raises a single high-severity incident when three or more of these fire from
the same host in a short window. That is the difference between an alert cannon and
usable detection.
