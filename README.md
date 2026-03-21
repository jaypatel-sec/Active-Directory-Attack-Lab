# Active Directory Attack Lab — Jay Patel

A complete 9-step Active Directory kill chain executed end-to-end in a home lab environment.
This lab documents the full offensive attack path from initial network-level credential poisoning
through domain persistence — covering the techniques that appear most frequently in real-world
Active Directory penetration tests and are tested directly in CPTS and OSCP.

Every attack folder contains the prerequisites, the exact commands run, real lab output, and a
detailed breakdown of what each step accomplishes and why it works. The goal is to build a
reproduce-ready reference for every stage of the AD kill chain that can be used during actual
engagements and certification labs.

---

## Lab Environment

| Machine | Role | OS |
|---|---|---|
| Kali Linux | Attacker workstation | Kali 2024.x |
| Windows Server 2022 | Domain Controller | Windows Server 2022 |
| Windows 10 22H2 | Victim workstation | Windows 10 22H2 |

The lab is built on a private virtual network with the domain controller fully configured with
Active Directory Domain Services, DNS, and a set of intentionally misconfigured accounts and
policies to simulate the conditions commonly found in real enterprise environments.

---

## Kill Chain — 9 Attack Steps

| # | Attack | MITRE ID | Technique Summary | Status |
|---|---|---|---|---|
| 01 | LLMNR Poisoning | T1557.001 | Intercept LLMNR/NBT-NS broadcasts to capture NTLMv2 hashes from any host that sends a failed name resolution request | ⏳ Pending |
| 02 | NTLMv2 Relay | T1557.001 | Relay captured NTLMv2 credentials to other machines on the network to authenticate as the victim without cracking the hash | ⏳ Pending |
| 03 | Password Spraying | T1110.003 | Test one or a small number of commonly used passwords against every domain account to avoid lockout thresholds | ⏳ Pending |
| 04 | Kerberoasting | T1558.003 | Request Kerberos service tickets for accounts with SPNs and crack the RC4-encrypted tickets offline | ⏳ Pending |
| 05 | AS-REP Roasting | T1558.004 | Request AS-REP responses for accounts with pre-authentication disabled and crack the encrypted portion offline | ⏳ Pending |
| 06 | Pass the Hash | T1550.002 | Authenticate to remote services using a captured NTLM hash without recovering the plaintext password | ⏳ Pending |
| 07 | Pass the Ticket | T1550.003 | Inject a stolen Kerberos ticket into the current session to impersonate a user and access resources | ⏳ Pending |
| 08 | Golden Ticket | T1558.001 | Forge a Kerberos TGT using the KRBTGT account hash to gain persistent, unlimited domain access | ⏳ Pending |
| 09 | DCSync | T1003.006 | Abuse domain replication privileges to pull NTLM hashes for all domain accounts directly from the DC | ⏳ Pending |

---

## Repository Structure

```
Active-Directory-Attack-Lab/
└── Attacks/
    ├── 01-LLMNR-Poisoning/
    │   └── attack-steps.md
    ├── 02-NTLMv2-Relay/
    │   └── attack-steps.md
    ├── 03-Password-Spraying/
    │   └── attack-steps.md
    ├── 04-Kerberoasting/
    │   └── attack-steps.md
    ├── 05-AS-REP-Roasting/
    │   └── attack-steps.md
    ├── 06-Pass-the-Hash/
    │   └── attack-steps.md
    ├── 07-Pass-the-Ticket/
    │   └── attack-steps.md
    ├── 08-Golden-Ticket/
    │   └── attack-steps.md
    └── 09-DCSync/
        └── attack-steps.md
```

Each `attack-steps.md` covers:
- **What the attack is** — the underlying protocol or mechanism being abused
- **Why it works** — the misconfiguration or design weakness that makes the attack possible
- **Prerequisites** — what access level, tools, and conditions are required before running this step
- **Step-by-step commands** — exact syntax with every flag explained
- **Real lab output** — actual terminal output captured during execution
- **What to do with the result** — how the output feeds into the next stage of the kill chain

---

## Tools Used

| Tool | Purpose | Used In |
|---|---|---|
| Responder | LLMNR/NBT-NS/MDNS poisoning and hash capture | 01 — LLMNR Poisoning |
| Impacket ntlmrelayx | NTLMv2 relay attacks | 02 — NTLMv2 Relay |
| CrackMapExec | Password spraying across domain accounts | 03 — Password Spraying |
| Impacket GetUserSPNs | SPN discovery and ticket request | 04 — Kerberoasting |
| Impacket GetNPUsers | AS-REP retrieval for pre-auth disabled accounts | 05 — AS-REP Roasting |
| CrackMapExec / Mimikatz | Hash-based authentication | 06 — Pass the Hash |
| Rubeus / Mimikatz | Ticket injection and manipulation | 07 — Pass the Ticket |
| Impacket secretsdump | DCSync and credential extraction | 08, 09 — Golden Ticket, DCSync |
| Hashcat | Offline cracking of captured hashes and tickets | Throughout |
| BloodHound / SharpHound | AD enumeration and attack path visualisation | Throughout |

---

## Attack Path Context

The kill chain is sequenced to reflect how a real engagement progresses from initial network access
to full domain compromise. Each step builds on the previous:

```
Passive Credential Capture (LLMNR/NTLMv2)
        ↓
Lateral Movement Preparation (Relay, Spray)
        ↓
Privilege Escalation (Kerberoasting, AS-REP)
        ↓
Domain User → Domain Admin (PTH, PTT)
        ↓
Full Domain Compromise + Persistence (Golden Ticket, DCSync)
```

This sequence mirrors the methodology tested in HTB Academy CPTS, HackTheBox Pro Labs,
and the OSCP Active Directory sets.

---

## Certification Alignment

| Certification | Relevant Techniques |
|---|---|
| eJPT | Password Spraying, basic credential attacks |
| HTB CPTS | Full kill chain — all 9 steps |
| OSCP | Kerberoasting, AS-REP, Pass the Hash, DCSync |
