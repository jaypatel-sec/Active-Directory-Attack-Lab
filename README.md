# Active Directory Attack Lab — Jay Patel

A full 9-step Active Directory kill chain executed in a home lab environment.
Every attack step includes: lab commands and real output, detection rules in SPL and KQL, and MITRE ATT&CK mapping.

This is the centrepiece of the portfolio — offensive execution paired with defensive detection on every step.

---

## Lab Environment

| Machine | Role | OS |
|---|---|---|
| Kali Linux | Attacker | Kali 2024.x |
| Windows Server | Domain Controller | Windows Server 2022 |
| Windows 10 | Victim Workstation | Windows 10 22H2 |

---

## Kill Chain Progress

| # | Attack | MITRE ID | Status | Detection |
|---|---|---|---|---|
| 01 | LLMNR Poisoning | T1557.001 | ⏳ Pending | ⏳ Pending |
| 02 | NTLMv2 Relay | T1557.001 | ⏳ Pending | ⏳ Pending |
| 03 | Password Spraying | T1110.003 | ⏳ Pending | ⏳ Pending |
| 04 | Kerberoasting | T1558.003 | ⏳ Pending | ⏳ Pending |
| 05 | AS-REP Roasting | T1558.004 | ⏳ Pending | ⏳ Pending |
| 06 | Pass the Hash | T1550.002 | ⏳ Pending | ⏳ Pending |
| 07 | Pass the Ticket | T1550.003 | ⏳ Pending | ⏳ Pending |
| 08 | Golden Ticket | T1558.001 | ⏳ Pending | ⏳ Pending |
| 09 | DCSync | T1003.006 | ⏳ Pending | ⏳ Pending |

---

## Repository Structure

```
Active-Directory-Attack-Lab/
├── Attacks/
│   ├── 01-LLMNR-Poisoning/
│   │   ├── attack-steps.md
│   │   ├── detection.md
│   │   ├── detection-splunk.spl
│   │   └── detection-sentinel.kql
│   ├── 02-NTLMv2-Relay/
│   ├── 03-Password-Spraying/
│   ├── 04-Kerberoasting/
│   ├── 05-AS-REP-Roasting/
│   ├── 06-Pass-the-Hash/
│   ├── 07-Pass-the-Ticket/
│   ├── 08-Golden-Ticket/
│   └── 09-DCSync/
└── Detection-Rules/
    ├── SPL/
    └── KQL/
```

---

## Detection Coverage

Every attack step produces:
- `attack-steps.md` — prerequisites, commands, real lab output, kill chain context
- `detection.md` — what the attack produces on the wire, IOCs, false positive considerations
- `detection-splunk.spl` — tested SPL query for Splunk
- `detection-sentinel.kql` — tested KQL rule for Microsoft Sentinel

All detection queries are also cross-posted to [SOC-Detection-Lab](https://github.com/jaypatel-sec/SOC-Detection-Lab).
