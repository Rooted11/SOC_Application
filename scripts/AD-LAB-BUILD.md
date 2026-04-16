# SOC Lab — Active Directory Build Guide

End-to-end build for a multi-DC + member-server Active Directory lab on Windows
Server 2022, sized to fit alongside the SOC stack at `<LAB_SUBNET>/24`.

## Topology

| Host | IP | Role | Site |
|------|----|------|------|
| **DC01** | <DC01_IP> | Forest root, FSMO holder, DNS, gMSA host | HQ-Site |
| **DC02** | <DC02_IP> | Additional writable DC, GC, DNS | HQ-Site |
| **DC03** | <DC03_IP> | Additional writable DC, GC, DNS | Branch-Site |
| **FS01** | <FS01_IP> | File Server, DFS-N, DHCP, AD CS, Print | HQ-Site |
| Ubuntu SOC | <SOC_UBUNTU_IP> | SOC stack (Wazuh / Splunk / custom) | — |
| Host | <VM_HOST_IP> | Hyper-V / VBox / VMware host | — |

Domain: **example.local** &nbsp;&nbsp; NetBIOS: **LAB**

> All four servers run **OpenSSH Server** on port 22 so they can be driven from
> the host with [`dc_ssh.py`](../../dc_ssh.py) and [`dc_push.py`](../../dc_push.py).

## Run order

Each script is **idempotent** — safe to re-run after fixing an issue.

| # | Where | Script | What it does |
|---|-------|--------|--------------|
| 1 | Fresh Win2022 | [`dc01-quick-setup.ps1`](dc01-quick-setup.ps1) | Static IP, rename, AD DS install, **promote to forest** (reboots) |
| 2 | DC01, after reboot | [`dc01-after-reboot.ps1`](dc01-after-reboot.ps1) or [`dc01-phase2.ps1`](dc01-phase2.ps1) | OUs, users, groups, audit policy |
| 3 | DC01 | [`dc01-advanced-ad.ps1`](dc01-advanced-ad.ps1) | **Recycle Bin, KDS key, gMSA, FGPP, Sites, reverse DNS, baseline GPOs, LAPS, Tier 0/1/2 OUs** |
| 4 | Fresh Win2022 (.11) | [`dc02-promote.ps1`](dc02-promote.ps1) | 2nd DC in HQ-Site (reboots) |
| 5 | Fresh Win2022 (.12) | [`dc03-promote.ps1`](dc03-promote.ps1) | 3rd DC in Branch-Site (reboots) |
| 6 | Fresh Win2022 (.20) | [`fs01-setup.ps1`](fs01-setup.ps1) | Member server: File / DFS / DHCP / AD CS / Print (runs in two passes around the join-reboot) |

After all DCs are up:
```powershell
Get-ADDomainController -Filter * | ft Name, Site, IPv4Address, OperatingSystem
repadmin /replsummary
repadmin /syncall /AdeP
dcdiag /v
```

## What `dc01-advanced-ad.ps1` adds

| Feature | Why it matters |
|---|---|
| **AD Recycle Bin** | One-click restore for deleted users / OUs (forest-wide, irreversible to disable) |
| **KDS Root Key + gMSA `svc-soc-fwd`** | Passwordless service account for the SOC log forwarder, rotated automatically |
| **PSO-Admins** | 16-char / 60-day / 5-attempt lockout for Domain Admins (overrides Default Domain Policy) |
| **PSO-ServiceAccounts** | 24-char / never expires for service accounts |
| **HQ-Site / Branch-Site + subnets** | Lets us exercise inter-site replication and site coverage |
| **Reverse DNS zone 56.168.192.in-addr.arpa** | PTR records for SOC log enrichment |
| **DNS scavenging** | Cleans stale records every 7 days |
| **Tier 0 / Tier 1 / Tier 2 OUs + groups** | Microsoft tier-isolation admin model — `T0-DomainAdmins`, `T1-ServerAdmins`, `T2-WorkstationAdmins` |
| **`SOC - Audit Baseline` GPO** | Forces 4688 cmdline logging on every server |
| **`SOC - Firewall On` GPO** | Domain/Standard/Public profiles all on, default-deny inbound |
| **`SOC - SMB Signing Required` GPO** | Mitigates SMB relay attacks |
| **`SOC - RDP Hardening` GPO** | Forces NLA + high encryption |
| **Protected Users membership** | `soc-admin` / `it-admin` get Kerberos AES + no NTLM/cached creds |
| **Windows LAPS schema** | Native LAPS attributes (requires inbox LAPS — see note below) |

### Windows LAPS note
Native (inbox) Windows LAPS requires Server 2022 build with **KB5025230 (April 2023)** or later.
On the GA build (`10.0.20348` baseline) the `Update-LapsADSchema` cmdlet is not present.
The script detects this and prints a hint. To enable LAPS:

```powershell
# install all pending Windows updates, reboot, then re-run:
.\dc01-advanced-ad.ps1
```

## What `fs01-setup.ps1` builds

A real "full server" with:

- **File Server + FSRM + Data Deduplication**
- **DFS Namespaces (`\\example.local\soc`) + DFS-R**
- **DHCP** (scope `<DHCP_START>-<DHCP_END>`, reservations for DCs and FS01)
- **AD CS Enterprise Root CA** (`SOC-Lab-Root-CA`, SHA256, 10y)
- **AD CS Web Enrollment** (`https://FS01/certsrv`)
- **Print Server**
- **Windows Server Backup**
- **OpenSSH Server**

Shares created:

| Share | Path | Access | Notes |
|---|---|---|---|
| `\\FS01\SOC$` | `D:\Shares\SOC` | Domain Admins (FC), SOC Analysts/Admins (Change) | hidden, encrypted, no caching |
| `\\FS01\Public` | `D:\Shares\Public` | Authenticated Users (Change) | 5 GB FSRM hard quota |
| `\\FS01\Profiles$` | `D:\Shares\Profiles` | Domain Users (Change) | for roaming profiles |
| `\\example.local\soc` | DFS-N root | Authenticated Users | with `public`, `tools`, `incidents` folder targets |

## Driving the build remotely from the host

The two helper scripts at the repo root make it possible to run everything from
the Windows host without RDP:

```bash
# push a script to DC01
python dc_push.py Lab-Repo-main/scripts/dc01-advanced-ad.ps1 C:/Lab/dc01-advanced-ad.ps1

# run it
python dc_ssh.py "powershell -NoProfile -ExecutionPolicy Bypass -File C:/Lab/dc01-advanced-ad.ps1"
```

Both connect as the DC01 local `Administrator`. Set the password in the local
`.env` (or your credential manager) — do not commit it. Edit the files to point
at DC02/DC03/FS01 once those VMs exist.

## Verification commands

```powershell
# Forest health
Get-ADForest | ft Name, ForestMode, GlobalCatalogs
Get-ADDomain | ft DNSRoot, DomainMode, PDCEmulator
Get-ADDomainController -Filter * | ft Name, Site, IPv4Address

# Recycle Bin
(Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'").EnabledScopes

# Sites & subnets
Get-ADReplicationSite -Filter * | ft Name
Get-ADReplicationSubnet -Filter * | ft Name, Site
Get-ADReplicationSiteLink -Filter * | ft Name, Cost, ReplicationFrequencyInMinutes

# Password policies
Get-ADFineGrainedPasswordPolicy -Filter * | ft Name, Precedence, MinPasswordLength

# gMSA
Get-ADServiceAccount -Filter * | ft Name, Enabled, PrincipalsAllowedToRetrieveManagedPassword

# GPOs
Get-GPO -All | ft DisplayName, GpoStatus
(Get-GPInheritance -Target (Get-ADDomain).DistinguishedName).GpoLinks | ft DisplayName, Enabled

# Replication
repadmin /replsummary
repadmin /showrepl
dcdiag /v
```

## Rollback

- **Recycle Bin** cannot be disabled — accept this when you run phase 3.
- **GPOs** can be unlinked with `Remove-GPLink` and removed with `Remove-GPO`.
- **PSOs** can be removed with `Remove-ADFineGrainedPasswordPolicy`.
- **gMSA** can be removed with `Remove-ADServiceAccount`.
- **Sites/Subnets** can be removed with `Remove-ADReplicationSubnet` / `Remove-ADReplicationSite`.
- **DCs** can be demoted with `Uninstall-ADDSDomainController`.
