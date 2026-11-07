# Active Directory Attack Techniques — Practical Lab Guide

Nine Active Directory attack techniques documented from separate HTB Academy lab examples,
covering techniques that appear most frequently in enterprise AD penetration tests and
certification labs (HTB CPTS, OSCP).

Each module contains root cause analysis, attack methodology, complete tooling syntax,
detection logic (Sigma rules + Windows Event IDs), and hardening recommendations.

> **Lab Source:** HTB Academy — Active Directory Penetration Tester Path (2024)
> **Environment:** INLANEFREIGHT.LOCAL — grey-box internal assessment scenario

---

## Lab Environment

| Hostname | Role | IP | OS |
|---|---|---|---|
| ACADEMY-EA-DC01 | Domain Controller | 172.16.5.5 | Windows Server 2019 |
| ACADEMY-EA-MS01 | Member Server / Jump Host | 172.16.5.25 | Windows Server 2019 |
| ACADEMY-EA-MX01 | Exchange / File Server | 172.16.5.50 | Windows Server 2016 |
| Attack Host | Kali Linux (Pwnbox) | 172.16.5.225 | Kali 2024.x |

**Domain:** `INLANEFREIGHT.LOCAL`
**Domain SID:** `S-1-5-21-3842939050-3880317879-2865463114`
**Network Range:** `172.16.5.0/23`
**Initial Access:** `htb-student:Academy_student_AD!` on MS01 (grey-box foothold)

> **Lab snapshot note:** The topology above is a reference snapshot. Individual modules may contain outputs from separate HTB Academy lab instances with different host mappings, IP assignments, and account sets. The environment, host mappings, credentials, and sample outputs documented within each module are authoritative for that module. Do not assume all examples represent one continuous attack chain run against the same environment.

---

## Conceptual Attack-Path Map

The diagram below is a **conceptual attack-path map** assembled from separate lab examples. It shows how these techniques chain together in a real engagement, but the individual modules were captured from independent HTB Academy lab instances. No single continuous run produced the entire sequence below.

```
[ Initial Foothold ]
  htb-student on ACADEMY-EA-MS01
          │
          ▼
[ 01 ] LLMNR / NBT-NS Poisoning
  Responder on 172.16.5.225 → captures forend NTLMv2 hash
  Hashcat -m 5600 → plaintext: Klmcargo2
          │
          ▼
[ 02 ] NTLMv2 Relay
  ntlmrelayx relay to ACADEMY-EA-MS01 → SAM dump / shell
          │
          ▼
[ 03 ] Password Spraying
  kerbrute / CME → avazquez:Password123 (domain user)
          │
          ▼
[ 04 ] Kerberoasting
  forend:Klmcargo2 → GetUserSPNs → SPN account TGS hashes (varies by snapshot)
  Hashcat -m 13100 → plaintext credentials
          │
          ▼
[ 05 ] AS-REP Roasting
  GetNPUsers → accounts with pre-auth disabled → AS-REP hash (varies by snapshot)
  Hashcat -m 18200 → plaintext
          │
          ▼
[ 06 ] Pass the Hash
  Recovered NT hash → CME / psexec.py → lateral movement without plaintext
          │
          ▼
[ 07 ] Pass the Ticket
  Rubeus dump → inject TGS into session → access as target user
          │
          ▼
[ 09 ] DCSync
  adunn (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All)
  secretsdump → all domain hashes including krbtgt
  INLANEFREIGHT\administrator, INLANEFREIGHT\krbtgt — full domain hash extraction
          │
          ▼ (KRBTGT long-term key material)
[ 08 ] Golden Ticket
  KRBTGT long-term key material — NT hash (RC4) or AES256 key (AES) — obtained via DCSync → ticketer.py / Rubeus → forge TGT
  Persistent domain access within the compromised domain
```

---

## Attack Modules

| # | Technique | MITRE | Status |
|---|---|---|---|
| [01](Attacks/01-LLMNR-Poisoning/README.md) | LLMNR / NBT-NS Poisoning | T1557.001 | ✅ Documented |
| [02](Attacks/02-NTLMv2-Relay/README.md) | NTLMv2 Relay | T1557.001 | ✅ Documented |
| [03](Attacks/03-Password-Spraying/README.md) | Password Spraying | T1110.003 | ✅ Documented |
| [04](Attacks/04-Kerberoasting/README.md) | Kerberoasting | T1558.003 | ✅ Documented |
| [05](Attacks/05-AS-REP-Roasting/README.md) | AS-REP Roasting | T1558.004 | ✅ Documented |
| [06](Attacks/06-Pass-the-Hash/README.md) | Pass the Hash | T1550.002 | ✅ Documented |
| [07](Attacks/07-Pass-the-Ticket/README.md) | Pass the Ticket | T1550.003 | ✅ Documented |
| [08](Attacks/08-Golden-Ticket/README.md) | Golden Ticket | T1558.001 | ✅ Documented |
| [09](Attacks/09-DCSync/README.md) | DCSync | T1003.006 | ✅ Documented |

---

## Repository Structure

```
Active-Directory-Attack-Lab/
└── Attacks/
    ├── 01-LLMNR-Poisoning/
    │   └── README.md
    ├── 02-NTLMv2-Relay/
    │   └── README.md
    ├── 03-Password-Spraying/
    │   └── README.md
    ├── 04-Kerberoasting/
    │   └── README.md
    ├── 05-AS-REP-Roasting/
    │   └── README.md
    ├── 06-Pass-the-Hash/
    │   └── README.md
    ├── 07-Pass-the-Ticket/
    │   └── README.md
    ├── 08-Golden-Ticket/
    │   └── README.md
    └── 09-DCSync/
        └── README.md
```

Each `README.md` covers:

- **Root cause** — the protocol or design weakness being abused
- **Attack chain** — ASCII flow from pre-condition to objective
- **Phase breakdown** — recon → exploitation → post-exploitation
- **Detection** — Sigma rules, Windows Event IDs, log artifacts
- **Hardening** — exact mitigations with implementation guidance
- **MITRE ATT&CK** — technique and sub-technique mapping

---

## Tooling Reference

| Tool | Purpose | Modules |
|---|---|---|
| Responder | LLMNR / NBT-NS / MDNS poisoning, NTLMv2 capture | 01 |
| Impacket ntlmrelayx | NTLMv2 relay to SMB targets | 02 |
| kerbrute | Domain user enumeration, password spraying | 03 |
| CrackMapExec (CME) | SMB spray, authentication, lateral movement | 03, 06 |
| Impacket GetUserSPNs | SPN discovery, TGS ticket request | 04 |
| Impacket GetNPUsers | AS-REP retrieval (no pre-auth) | 05 |
| Rubeus | Kerberos ticket operations (request, dump, inject, forge) | 05, 07, 08 |
| Mimikatz | Credential extraction, ticket export, DCSync | 06, 07, 08, 09 |
| Impacket secretsdump | Remote credential dumping, DCSync | 09 |
| Impacket psexec / wmiexec | Remote execution via hash | 06 |
| Hashcat | Offline hash cracking (NTLMv2, TGS-REP, AS-REP) | 01, 04, 05 |
| BloodHound / SharpHound | AD graph enumeration, attack path analysis | Throughout |
| PowerView | AD enumeration, ACL analysis | Throughout |

---

## Representative Accounts by Module

> These accounts appear in module examples and may not all coexist in the same lab snapshot. Each module's documented credentials and accounts are authoritative for that module only.

| Account | Module | Type | Notes |
|---|---|---|---|
| htb-student | All | Domain User | Initial grey-box foothold |
| forend | 01, 02 | Domain User | Captured via LLMNR (Klmcargo2) |
| avazquez | 03 | Domain User | Password spray hit (Password123) |
| sqldev / sqlprod / sqlqa | 04 | Service Accounts | Kerberoastable (SPN-bearing accounts in Module 04 snapshot) |
| BACKUPAGENT / SOLARWINDSMONITOR | 04 | Service Accounts | Kerberoastable (Module 04 snapshot) |
| amber.smith / jenna.smith | 05 | Domain Users | AS-REP roastable examples in Module 05 snapshot |
| adunn | 09 | Domain User | Holds DS-Replication-Get-Changes AND DS-Replication-Get-Changes-All |
| administrator | 06, 09 | Domain Admin | Full domain compromise objective |
| krbtgt | 08, 09 | Built-in | Hash extracted via DCSync → used for Golden Ticket |

---

## Certification Alignment

| Certification | Relevant Modules |
|---|---|
| HTB CPTS | All 9 — coverage of nine documented AD attack techniques |
| OSCP | 03, 04, 05, 06, 07, 09 |
| eJPT | 03, 06 |
| eWPTX | 06, 07 |

---

## Detection Coverage

Each module documents the Windows Event IDs and Sigma rule conditions that detect
that technique in a monitored environment.

| Technique | Primary Detection Events |
|---|---|
| LLMNR Poisoning | LLMNR/NBT-NS response anomalies, unexpected name-resolution responders, suspicious SMB authentication destinations, network packet analysis |
| NTLMv2 Relay | Event 4624 (Type 3 logon), network signatures |
| Password Spraying | Event 4625 (failed logon), 4771 (Kerberos pre-auth failure) |
| Kerberoasting | Event 4769 (TGS requests for SPN-bearing accounts); RC4 encryption type is a useful additional signal where AES is expected, not a requirement for detection |
| AS-REP Roasting | Event 4768 with Pre-Authentication Type 0 |
| Pass the Hash | Event 4624 (Type 3, NTLM auth) |
| Pass the Ticket | Event 4768, 4769, abnormal ticket usage |
| Golden Ticket | Event 4769 anomalies; correlate with Kerberos events and identity telemetry |
| DCSync | Event 4662 (Directory replication rights exercised) |

---

## References

- [HTB Academy — Active Directory Penetration Tester Path](https://academy.hackthebox.com/path/preview/active-directory-penetration-tester)
- [MITRE ATT&CK — Enterprise Matrix (Windows)](https://attack.mitre.org/matrices/enterprise/windows/)
- [Impacket](https://github.com/fortra/impacket) · [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) · [Rubeus](https://github.com/GhostPack/Rubeus)
- [Responder](https://github.com/lgandx/Responder) · [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- SpecterOps — [Certified Pre-Owned](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- Harmj0y — [The Most Dangerous Consistency: Kerberoasting](http://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
