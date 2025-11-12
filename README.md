# 🛡️ AD Hardening Playbook Ultimate
**Advanced Active Directory Security Audit & Safe Remediation Toolkit**  
by [Raffaele Fusco](https://www.linkedin.com/in/raffaelefusco/)  
License: [MIT](./LICENSE)

---

## 🌍 Overview
**AD-Hardening-Playbook-Ultimate.ps1** è uno script PowerShell enterprise-grade progettato per **auditing, remediation e reporting** della sicurezza di un ambiente Active Directory.

👉 È pensato per:
- team **IT Security / Infrastructure**
- **pentester difensivi** o **auditor**
- system engineer che vogliono **automatizzare il controllo delle policy critiche**

Lo script combina in un’unica soluzione:
- Audit multipli e parametrici (SMBv1, NTLM, RDP, LAPS, LDAP, Kerberos)
- Backup GPO automatici (completo e selettivo)
- Dashboard HTML interattiva (grafici + heatmap)
- Modalità *dry-run* sicura + remediation controllata

---

## 🧩 Features

| Categoria | Descrizione | Severità stimata |
|------------|--------------|------------------|
| 🔹 **SMBv1** | Scansione e disabilitazione feature legacy | 🔥 High |
| 🔹 **NTLM Compatibility** | Verifica livello `LmCompatibilityLevel` | 🔥 High |
| 🔹 **RDP NLA** | Controllo autenticazione di rete su host server | ⚠️ Medium |
| 🔹 **Local Admins** | Enumerazione membri gruppo Administrators locali | ⚠️ Medium |
| 🔹 **LAPS** | Verifica schema, estensione client, GPO attiva | 🔥 High |
| 🔹 **LDAP Signing / Channel Binding** | Controllo chiavi `LDAPServerIntegrity` e `ChannelBindingToken` | 🔥 High |
| 🔹 **Kerberos Ticket Lifetime** | Controllo `MaxTicketAge`, `MaxRenewAge`, `MaxServiceAge` | ⚠️ Medium |
| 🔹 **GPO Backup** | Backup selettivo (DDP/DDCP) + completo pre-remediation | 🟢 Safe |
| 🔹 **Dashboard HTML** | Chart.js + Heatmap Host × Categoria | 💎 Visual |

---

## 📁 Output
Dopo l’esecuzione, lo script genera automaticamente:

C:\Temp
├─ ADHardeningReport_YYYYMMDD_HHmmss
│ ├─ findings.json
│ ├─ findings.csv
│ ├─ report.html
│ ├─ dashboard.html
│ ├─ run.log
│ └─ ADHardening_YYYYMMDD_HHmmss.zip
│
├─ GPO_Backups
│ └─ GPOBackup_YYYYMMDD_HHmmss
│ ├─ GPO_Backup_Manifest.json
│ └─ [Backup GPO files...]
│
└─ GPO_Backups_Selective
├─ Default_Domain_Policy.zip
└─ Default_Domain_Controllers_Policy.zip


---

## ⚙️ Utilizzo

### ✅ Modalità Dry-Run (default)
Esegue **tutti i controlli**, genera **report e dashboard**, ma **non applica modifiche**.

```powershell
.\AD-Hardening-Playbook-Ultimate.ps1

### ✅ Modalità Apply

.\AD-Hardening-Playbook-Ultimate.ps1 -Apply
# oppure
.\AD-Hardening-Playbook-Ultimate.ps1 -Apply -Force
