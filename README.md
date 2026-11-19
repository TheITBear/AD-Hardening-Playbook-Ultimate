# 🛡️ AD Hardening Playbook Ultimate
**Advanced Active Directory Security Audit & Safe Remediation Toolkit**  
by [Raffaele Fusco]([https://www.linkedin.com/in/raffaele-fusco-it/])  
License: [MIT](./LICENSE)

---

## 🌍 Overview
**AD-Hardening-Playbook-Ultimate.ps1** is an enterprise-grade PowerShell script designed for **auditing, remediation, and reporting** on Active Directory security.

👉 It’s built for:
- **IT Security / Infrastructure** teams  
- **Defensive pentesters** or **security auditors**  
- **System engineers** who want to **automate the enforcement of critical policies**

This script combines multiple functions in one solution:
- Multi-layered and parameterized audits (SMBv1, NTLM, RDP, LAPS, LDAP, Kerberos)  
- Automatic GPO backups (full and selective)  
- Interactive HTML dashboard (charts + heatmap)  
- Safe *dry-run* mode + controlled remediation

---

## 🧩 Features

| Category | Description | Estimated Severity |
|-----------|-------------|--------------------|
| 🔹 **SMBv1** | Scan and disable legacy SMBv1 feature | 🔥 High |
| 🔹 **NTLM Compatibility** | Check `LmCompatibilityLevel` setting | 🔥 High |
| 🔹 **RDP NLA** | Verify Network Level Authentication on servers | ⚠️ Medium |
| 🔹 **Local Admins** | Enumerate members of local Administrators groups | ⚠️ Medium |
| 🔹 **SMB Signing** | Check `RequireSecuritySignature` on SMB server | ⚠️ Medium |
| 🔹 **LAPS** | Legacy + Windows LAPS: schema check and real coverage (% of enabled computers with a managed password) | 🔥 High |
| 🔹 **LDAP Signing / Channel Binding** | Validate `LDAPServerIntegrity` and `LdapEnforceChannelBinding` | 🔥 High |
| 🔹 **Kerberos Ticket Lifetime** | Audit `MaxTicketAge`, `MaxRenewAge`, `MaxServiceAge` | ⚠️ Medium |
| 🔹 **GPO Backup** | Selective (DDP/DDCP) + full backup before remediation | 🟢 Safe |
| 🔹 **HTML Dashboard** | Chart.js + Host × Category heatmap | 💎 Visual |

---

📁 Output
After execution, the script automatically generates:
C:\Temp
├─ ADHardeningReport_YYYYMMDD_HHmmss
│   ├─ findings.json
│   ├─ findings.csv
│   ├─ report.html
│   ├─ dashboard.html
│   ├─ run.log
│   └─ ADHardening_YYYYMMDD_HHmmss.zip
│
├─ GPO_Backups
│   └─ GPOBackup_YYYYMMDD_HHmmss
│       ├─ GPO_Backup_Manifest.json
│       └─ [Backup GPO files...]
│
│   └─ Selective_YYYYMMDD_HHmmss
│       ├─ Default_Domain_Policy.zip
│       └─ Default_Domain_Controllers_Policy.zip



---

## ⚙️ Usage

### ✅ Dry-Run Mode (default)
Performs **all security checks**, generates **reports and dashboard**, but **applies no changes**.

.\AD-Hardening-Playbook-Ultimate.ps1

✅ Apply Mode
### Executes safe remediations after automatically creating a full GPO backup.

.\AD-Hardening-Playbook-Ultimate.ps1 -Apply
# or
.\AD-Hardening-Playbook-Ultimate.ps1 -Apply -Force

### 🔧 Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Apply` | off | Apply remediations (full GPO backup first) |
| `-Force` | off | Skip confirmation prompt |
| `-ExportPath` | `C:\Temp\ADHardeningReport_<timestamp>` | Report folder |
| `-BackupPath` | `C:\Temp\GPO_Backups` | GPO backup root |
| `-MaxServers` | 150 | Max member servers to scan (0 = all) |
| `-StaleDays` | 90 | Skip computers not logged on for N days (0 = off) |
| `-ThrottleLimit` | 32 | Parallel WinRM connections |
| `-ConnectTimeoutSec` | 15 | WinRM connect timeout per host |
| `-OperationTimeoutSec` | 120 | WinRM operation timeout per host |
| `-VerboseLog` | off | Print INFO/DEBUG to console |

Requirements: Windows PowerShell 5.1+, RSAT (ActiveDirectory + GroupPolicy modules), WinRM enabled on targets, read access to AD/GPOs (admin rights on targets for registry/local group queries).

---

## 📝 Changelog

### v2.0
- **Fixed parser errors** on Windows PowerShell 5.1 (`"$var:"` inside strings → `${var}`), file is now pure ASCII (BOM-less UTF-8 em dash was read as a smart quote by PS 5.1).
- **Fixed** `Invoke-Command -TimeoutSec` (parameter does not exist: every host was reported as *Unreachable*). Timeouts now via `New-PSSessionOption`.
- **Fixed** selective GPO backup (`Backup-GPO` requires an existing folder; zip collisions on re-run).
- **Fixed** final zip creation (zip was written inside the folder being compressed → file-in-use error).
- **Fixed** Kerberos audit: wrong XPath (never matched) and wrong thresholds (`MaxServiceAge` is in minutes, `MaxRenewAge` in days).
- **Fixed** LDAP channel binding registry value (`LdapEnforceChannelBinding`, not `ChannelBindingToken`).
- **Fixed** Local Admins false positives (local accounts like `HOST\Administrator` were reported as domain accounts); uses well-known SID `S-1-5-32-544` (localized OS), ADSI fallback for orphaned SIDs, `Domain Admins` excluded, DCs skipped.
- **Fixed** unreachable hosts flagged as "NLA not enabled" and targeted by remediation; `LmCompatibilityLevel` not set (default 3) now flagged.
- **Fixed** dashboard JS crash with a single severity/category (JSON object instead of array) and empty-findings crash; HTML output is now encoded.
- **Faster**: remote checks run in parallel (native `Invoke-Command` fan-out, `-ThrottleLimit`) in 3 batches instead of 5 sequential per-host loops; disabled/stale computers and DCs excluded from the member-server scan; FQDN targets (Kerberos, no NTLM fallback); slow DISM query only when needed.
- **New**: SMB signing audit, Windows LAPS support with real coverage %, SMBv1 remediation applied immediately via `Set-SmbServerConfiguration` (no reboot needed for the server side).

---

## 🧩 Dashboard Preview

****<img width="1536" height="1024" alt="dashboard-preview" src="https://github.com/user-attachments/assets/a75b1d0a-bb16-41c7-9f25-ba63a37b59a7" />


