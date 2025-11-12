🛡️ AD Hardening Playbook Ultimate
Advanced Active Directory Security Audit & Safe Remediation Toolkit
by Raffaele Fusco
License: MIT

🌍 Overview
AD-Hardening-Playbook-Ultimate.ps1 is an enterprise-grade PowerShell script designed for auditing, remediation, and reporting on Active Directory security.
👉 It’s built for:


IT Security / Infrastructure teams


Defensive pentesters or security auditors


System engineers who want to automate the enforcement of critical policies


This script combines multiple functions in one solution:


Multi-layered and parameterized audits (SMBv1, NTLM, RDP, LAPS, LDAP, Kerberos)


Automatic GPO backups (full and selective)


Interactive HTML dashboard (charts + heatmap)


Safe dry-run mode + controlled remediation



🧩 Features
CategoryDescriptionEstimated Severity🔹 SMBv1Scan and disable legacy SMBv1 feature🔥 High🔹 NTLM CompatibilityCheck LmCompatibilityLevel setting🔥 High🔹 RDP NLAVerify Network Level Authentication on servers⚠️ Medium🔹 Local AdminsEnumerate members of local Administrators groups⚠️ Medium🔹 LAPSCheck schema, client extension, and GPO status🔥 High🔹 LDAP Signing / Channel BindingValidate LDAPServerIntegrity and ChannelBindingToken🔥 High🔹 Kerberos Ticket LifetimeAudit MaxTicketAge, MaxRenewAge, MaxServiceAge⚠️ Medium🔹 GPO BackupSelective (DDP/DDCP) + full backup before remediation🟢 Safe🔹 HTML DashboardChart.js + Host × Category heatmap💎 Visual

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
└─ GPO_Backups_Selective
    ├─ Default_Domain_Policy.zip
    └─ Default_Domain_Controllers_Policy.zip


⚙️ Usage
✅ Dry-Run Mode (default)
Performs all security checks, generates reports and dashboard, but applies no changes.
.\AD-Hardening-Playbook-Ultimate.ps1

✅ Apply Mode
Executes safe remediations after automatically creating a full GPO backup.
.\AD-Hardening-Playbook-Ultimate.ps1 -Apply
# or
.\AD-Hardening-Playbook-Ultimate.ps1 -Apply -Force
