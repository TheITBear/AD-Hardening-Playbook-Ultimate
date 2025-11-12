<#
MIT License
Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>

<#
.SYNOPSIS
  AD-Hardening-Playbook-Ultimate.ps1 — Generic, enterprise-grade AD audit + safe remediation (EN version).

.DESCRIPTION
  - Performs AD/Windows security checks:
      * SMBv1, NTLM, RDP NLA, Local Admins
      * LAPS (client/GPO/attributes)
      * LDAP Signing & Channel Binding (DC)
      * Kerberos ticket lifetime (DDP/DDCP)
  - Generates JSON/CSV/HTML reports and an advanced HTML dashboard (Chart.js + heatmap)
  - Always performs selective GPO backups (DDP/DDCP); performs a full GPO backup before remediation
  - Supports safe remediation (on request) with dry-run by default

.PARAMETER Apply
  If present, applies safe remediations (a full GPO backup is performed first).

.PARAMETER ExportPath
  Output directory for reports. Default: C:\Temp\ADHardeningReport\YYYYMMDD_HHmmss

.PARAMETER BackupPath
  Root directory for GPO backups. Default: C:\Temp\GPO_Backups

.PARAMETER Force
  Skips interactive confirmation prompts during Apply.

.PARAMETER VerboseLog
  Print verbose logs to console (a run.log is always written).

.EXAMPLE
  .\AD-Hardening-Playbook-Ultimate.ps1
  .\AD-Hardening-Playbook-Ultimate.ps1 -Apply -Force
#>

param(
    [switch]$Apply = $false,
    [string]$ExportPath = "",
    [string]$BackupPath = "C:\Temp\GPO_Backups",
    [switch]$Force = $false,
    [switch]$VerboseLog = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============= Logging & Utilities =============
function Write-Log {
    param([string]$Message, [ValidateSet("INFO","WARN","ERROR","DEBUG")] [string]$Level="INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$ts [$Level] $Message"
    if ($VerboseLog -or $Level -in @("WARN","ERROR")) { Write-Host $line }
    if ($Global:LogFile) { Add-Content -Path $Global:LogFile -Value $line }
}

function Ensure-Module {
    param([Parameter(Mandatory)] [string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Log "Module not found: $Name — attempting installation (CurrentUser)..." "WARN"
        try {
            Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        } catch {
            Write-Log "Install-Module $Name failed: $_" "ERROR"; throw
        }
    }
    Import-Module $Name -ErrorAction Stop
    Write-Log "Module loaded: $Name" "DEBUG"
}

# ============= Preflight & Paths =============
if (-not $ExportPath) {
    $ExportPath = Join-Path "C:\Temp" ("ADHardeningReport_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
}
New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
$Global:LogFile = Join-Path $ExportPath "run.log"

Write-Log "ExportPath: $ExportPath"
Write-Log "BackupPath: $BackupPath"

function Preflight {
    Write-Log "Running preflight checks..."
    Ensure-Module -Name ActiveDirectory
    Ensure-Module -Name GroupPolicy
    try {
        $dom = Get-ADDomain -ErrorAction Stop
        Write-Log "Domain detected: $($dom.DNSRoot)"
    } catch {
        Write-Log "Unable to query AD domain. Check RSAT/permissions/connectivity." "ERROR"
        throw
    }
}
Preflight

# ============= Helpers: Inventory =============
function Get-DomainControllers {
    Get-ADDomainController -Filter * | Select-Object HostName,Site,IPv4Address,OperatingSystem
}

function SevScore([string]$s) {
    switch ($s) { "High" {3} "Medium" {2} "Low" {1} default {0} }
}

# ============= AUDIT: Core =============
function Audit-SMBv1 {
    Write-Log "Auditing SMBv1 on a server sample..."
    $hosts = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Properties OperatingSystem |
             Select-Object -ExpandProperty Name -First 150
    $out = @()
    foreach ($h in $hosts) {
        try {
            $state = Invoke-Command -ComputerName $h -ScriptBlock {
                $f = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
                if ($f) { $f.State } else { "Unknown" }
            } -ErrorAction Stop -TimeoutSec 25
            $out += [pscustomobject]@{Host=$h; SMBv1=$state}
        } catch {
            $out += [pscustomobject]@{Host=$h; SMBv1="Unreachable"}
        }
    }
    $out
}

function Audit-NTLM {
    Write-Log "Auditing NTLM (LmCompatibilityLevel) on Domain Controllers..."
    $dcs = Get-DomainControllers | Select-Object -ExpandProperty HostName
    $out = @()
    foreach ($dc in $dcs) {
        try {
            $val = Invoke-Command -ComputerName $dc -ScriptBlock {
                (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
            } -ErrorAction Stop
            $out += [pscustomobject]@{DC=$dc; LmCompatibilityLevel=$val}
        } catch {
            $out += [pscustomobject]@{DC=$dc; LmCompatibilityLevel="Unreachable"}
        }
    }
    $out
}

function Audit-RDP {
    Write-Log "Auditing RDP (NLA/SecurityLayer) on a server sample..."
    $hosts = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} | Select-Object -ExpandProperty Name -First 120
    $out = @()
    foreach ($h in $hosts) {
        try {
            $r = Invoke-Command -ComputerName $h -ScriptBlock {
                $reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
                @{NLA=$reg.UserAuthentication; SecurityLayer=$reg.SecurityLayer}
            } -ErrorAction Stop -TimeoutSec 12
            $out += [pscustomobject]@{Host=$h; NLA=$r.NLA; SecurityLayer=$r.SecurityLayer}
        } catch {
            $out += [pscustomobject]@{Host=$h; NLA="Unreachable"; SecurityLayer="Unreachable"}
        }
    }
    $out
}

function Audit-LocalAdmins {
    Write-Log "Auditing local Administrators membership on a server sample..."
    $hosts = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} | Select-Object -ExpandProperty Name -First 80
    $out = @()
    foreach ($h in $hosts) {
        try {
            $members = Invoke-Command -ComputerName $h -ScriptBlock {
                (Get-LocalGroupMember -Group "Administrators") | Select-Object Name, ObjectClass
            } -ErrorAction Stop -TimeoutSec 15
            $out += [pscustomobject]@{Host=$h; Admins=$members}
        } catch {
            $out += [pscustomobject]@{Host=$h; Admins="Unreachable or PermissionDenied"}
        }
    }
    $out
}

# ============= AUDIT: Advanced (LAPS / LDAP / Kerberos) =============
function Audit-LAPS {
    Write-Log "Auditing LAPS (schema, client extension, and GPO presence)..."
    $hasClient = Test-Path "C:\Program Files\LAPS\AdmPwd.dll"
    $lapsGpo   = Get-GPO -All | Where-Object { $_.DisplayName -match "LAPS|Local Administrator Password" }

    $hasAttrs = $false
    try {
        $sample = Get-ADObject -LDAPFilter "(objectClass=computer)" -SearchBase (Get-ADDomain).DistinguishedName `
                 -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime -ResultSetSize 5
        if ($sample) { $hasAttrs = $true }
    } catch { $hasAttrs = $false }

    $finds = @()
    if (-not $hasClient -or -not $lapsGpo -or -not $hasAttrs) {
        $msg = "LAPS not fully implemented (Client:$hasClient, GPO:$([bool]$lapsGpo), Attributes:$hasAttrs)"
        $finds += [pscustomobject]@{ Category="LAPS"; Host="Domain"; Issue=$msg; Severity="High"; Remediation="Deploy LAPS client + apply LAPS GPO + ensure schema/attributes" }
    }
    $finds
}

function Audit-LDAPSigning {
    Write-Log "Auditing LDAP Signing & Channel Binding (Domain Controllers)..."
    $dcs = Get-DomainControllers | Select-Object -ExpandProperty HostName
    $finds = @()
    foreach ($dc in $dcs) {
        try {
            $vals = Invoke-Command -ComputerName $dc -ScriptBlock {
                @{
                    LDAPServerIntegrity = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
                    ChannelBindingToken = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "ChannelBindingToken" -ErrorAction SilentlyContinue).ChannelBindingToken
                }
            } -ErrorAction Stop
            if (($vals.LDAPServerIntegrity -lt 2) -or ($vals.ChannelBindingToken -lt 2)) {
                $finds += [pscustomobject]@{
                    Category="LDAP"; Host=$dc; Issue="LDAP Signing/Channel Binding not set to Require (LSI=$($vals.LDAPServerIntegrity), CBT=$($vals.ChannelBindingToken))"
                    Severity="High"; Remediation="Set LDAPServerIntegrity=2 and ChannelBindingToken=2 via GPO"
                }
            }
        } catch {
            $finds += [pscustomobject]@{
                Category="LDAP"; Host=$dc; Issue="DC unreachable for LDAP audit"; Severity="Medium"; Remediation="Verify WinRM/permissions"
            }
        }
    }
    $finds
}

function Audit-KerberosLifetime {
    Write-Log "Auditing Kerberos ticket lifetime (Default Domain / Domain Controllers Policies)..."
    $finds = @()
    try {
        $ddp  = Get-GPO -Name "Default Domain Policy" -ErrorAction Stop
        $ddcp = Get-GPO -Name "Default Domain Controllers Policy" -ErrorAction Stop

        [xml]$ddpXml  = Get-GPOReport -Guid $ddp.Id -ReportType Xml
        [xml]$ddcpXml = Get-GPOReport -Guid $ddcp.Id -ReportType Xml

        $keys = @("MaxTicketAge","MaxRenewAge","MaxServiceAge")
        foreach ($k in $keys) {
            $n1 = $ddpXml.SelectSingleNode("//Policy[@name='$k']/SettingNumber")
            if ($n1 -and [int]$n1.InnerText -gt 10) {
                $finds += [pscustomobject]@{ Category="Kerberos"; Host="DefaultDomainPolicy"; Issue="$k too high ($($n1.InnerText))"; Severity="Medium"; Remediation="Reduce $k (e.g., MaxTicketAge <= 10)" }
            }
            $n2 = $ddcpXml.SelectSingleNode("//Policy[@name='$k']/SettingNumber")
            if ($n2 -and [int]$n2.InnerText -gt 10) {
                $finds += [pscustomobject]@{ Category="Kerberos"; Host="DefaultDomainControllersPolicy"; Issue="$k too high ($($n2.InnerText))"; Severity="Medium"; Remediation="Reduce $k consistent with domain policy" }
            }
        }
    } catch {
        $finds += [pscustomobject]@{ Category="Kerberos"; Host="Domain"; Issue="Unable to read DDP/DDCP ($_)"; Severity="Low"; Remediation="Check GPO permissions" }
    }
    $finds
}

# ============= Findings Synthesis & Reporting =============
function Build-Findings {
    param(
        $smb, $ntlm, $rdp, $localAdmins, $laps, $ldap, $kerb
    )
    $finds = @()

    if ($laps) { $finds += $laps }
    if ($ldap) { $finds += $ldap }
    if ($kerb) { $finds += $kerb }

    foreach ($n in $ntlm) {
        if ($n.LmCompatibilityLevel -is [int] -and $n.LmCompatibilityLevel -lt 5) {
            $finds += [pscustomobject]@{
                Category="NTLM"; Host=$n.DC; Issue="LmCompatibilityLevel is low ($($n.LmCompatibilityLevel))"; Severity="High"; Remediation="Set LmCompatibilityLevel=5 (NTLMv2 only)"
            }
        } elseif ($n.LmCompatibilityLevel -eq "Unreachable") {
            $finds += [pscustomobject]@{
                Category="Connectivity"; Host=$n.DC; Issue="DC unreachable (NTLM audit)"; Severity="Medium"; Remediation="Verify connectivity/permissions"
            }
        }
    }

    foreach ($r in $smb) {
        if ($r.SMBv1 -eq "Enabled") {
            $finds += [pscustomobject]@{
                Category="SMBv1"; Host=$r.Host; Issue="SMBv1 enabled"; Severity="High"; Remediation="Disable SMBv1 (feature/registry)"
            }
        } elseif ($r.SMBv1 -eq "Unreachable") {
            $finds += [pscustomobject]@{
                Category="Connectivity"; Host=$r.Host; Issue="Host unreachable (SMB audit)"; Severity="Medium"; Remediation="Verify WinRM/permissions"
            }
        } elseif ($r.SMBv1 -ne "Disabled" -and $r.SMBv1 -ne $null -and $r.SMBv1 -ne "Unknown") {
            $finds += [pscustomobject]@{
                Category="SMBv1"; Host=$r.Host; Issue="SMBv1 state: $($r.SMBv1)"; Severity="High"; Remediation="Disable SMBv1"
            }
        }
    }

    foreach ($r in $rdp) {
        if ($r.NLA -ne 1) {
            $finds += [pscustomobject]@{
                Category="RDP"; Host=$r.Host; Issue="NLA not enabled"; Severity="Medium"; Remediation="Enable NLA"
            }
        }
    }

    foreach ($la in $localAdmins) {
        if ($la.Admins -isnot [string]) {
            foreach ($m in $la.Admins) {
                if ($m.Name -match "\\") {
                    $finds += [pscustomobject]@{
                        Category="LocalAdmins"; Host=$la.Host; Issue="Domain account in local Administrators: $($m.Name)"; Severity="Medium"; Remediation="Reduce privileges / delegated group / LAPS"
                    }
                }
            }
        } elseif ($la.Admins -like "Unreachable*") {
            $finds += [pscustomobject]@{
                Category="Connectivity"; Host=$la.Host; Issue="$($la.Admins)"; Severity="Low"; Remediation="Verify WinRM/permissions"
            }
        }
    }

    $finds
}

function Export-Findings {
    param([Parameter(Mandatory)] $Findings, [Parameter(Mandatory)] [string]$OutDir)

    $json = Join-Path $OutDir "findings.json"
    $csv  = Join-Path $OutDir "findings.csv"
    $Findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $json -Encoding UTF8
    $Findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Log "Findings exported: $json ; $csv"

    return @{ Json=$json; Csv=$csv }
}

function Build-HTMLReport {
    param($Findings, [string]$OutFile)
    $now = Get-Date
    $html = @"
<html>
<head><meta charset='utf-8'><title>AD Hardening Report - $($now)</title>
<style>
body{font-family:Segoe UI,Arial;margin:16px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:6px;font-size:13px}
th{background:#f4f4f4;text-align:left}
.badge{padding:2px 6px;border-radius:4px}
.sev-High{background:#ffdddd;border:1px solid #ff9d9d}
.sev-Medium{background:#fff1cc;border:1px solid #ffd666}
.sev-Low{background:#ddffdd;border:1px solid #9dff9d}
</style>
</head>
<body>
<h1>AD Hardening Report</h1>
<p>Generated: $($now)</p>
<table>
<tr><th>Category</th><th>Host</th><th>Issue</th><th>Severity</th><th>Remediation</th></tr>
"@
    foreach ($f in $Findings) {
        $sev = $f.Severity
        $cls = "sev-$sev"
        $html += "<tr><td>$($f.Category)</td><td>$($f.Host)</td><td>$($f.Issue)</td><td><span class='badge $cls'>$sev</span></td><td>$($f.Remediation)</td></tr>`n"
    }
    $html += "</table></body></html>"
    $html | Out-File -FilePath $OutFile -Encoding UTF8
}

function Build-HTMLDashboard {
    param($Findings, [string]$OutFile)

    $bySeverity = $Findings | Group-Object Severity | ForEach-Object { [pscustomobject]@{Severity=$_.Name; Count=$_.Count} }
    $byCategory = $Findings | Group-Object Category | ForEach-Object { [pscustomobject]@{Category=$_.Name; Count=$_.Count} }
    $hosts      = ($Findings | Select-Object -ExpandProperty Host | Sort-Object -Unique)
    $cats       = ($Findings | Select-Object -ExpandProperty Category | Sort-Object -Unique)

    $matrix = @()
    foreach ($h in $hosts) {
        $row = @{ Host=$h }
        foreach ($c in $cats) {
            $hit = $Findings | Where-Object { $_.Host -eq $h -and $_.Category -eq $c }
            if ($hit) {
                $max = ($hit | Sort-Object { SevScore $_.Severity } -Descending | Select-Object -First 1).Severity
                $row[$c] = $max
            } else { $row[$c] = "" }
        }
        $matrix += [pscustomobject]$row
    }

    $sevJson = ($bySeverity | ConvertTo-Json -Depth 6)
    $catJson = ($byCategory | ConvertTo-Json -Depth 6)
    $hostsJs = ($hosts | ConvertTo-Json -Depth 4)
    $catsJs  = ($cats  | ConvertTo-Json -Depth 4)
    $matJs   = ($matrix| ConvertTo-Json -Depth 6)
    $now = Get-Date

    $html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>AD Hardening Dashboard - $($now)</title>
<style>
body{font-family:Segoe UI,Arial;margin:16px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:24px}
.card{border:1px solid #ddd;border-radius:8px;padding:12px}
h2{margin:6px 0 12px 0}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #eee;padding:6px}
th{background:#fafafa;text-align:left;position:sticky;top:0}
.heat-L3{background:#ff6b6b}
.heat-L2{background:#ffd166}
.heat-L1{background:#95e06c}
.heat-L0{background:#f3f3f3}
.small{font-size:12px;color:#555}
</style>
</head>
<body>
<h1>AD Hardening Dashboard</h1>
<p class="small">Generated: $($now)</p>

<div class="grid">
  <div class="card">
    <h2>Severity Distribution</h2>
    <canvas id="sevChart" height="180"></canvas>
  </div>
  <div class="card">
    <h2>Issues by Category</h2>
    <canvas id="catChart" height="180"></canvas>
  </div>
</div>

<div class="card" style="margin-top:24px;">
  <h2>Heatmap: Host × Category</h2>
  <div style="overflow:auto; max-height:540px; border:1px solid #eee;">
    <table id="heatTable"><thead><tr><th>Host</th>
"@
    foreach ($c in $cats) { $html += "<th>$c</th>" }
    $html += "</tr></thead><tbody>"

    foreach ($row in $matrix) {
        $html += "<tr><td><b>$($row.Host)</b></td>"
        foreach ($c in $cats) {
            $sev = [string]$row.$c
            $score = switch ($sev) { "High" {3} "Medium" {2} "Low" {1} default {0} }
            $cls = "heat-L$score"
            $disp = if ($sev) { $sev } else { "" }
            $html += "<td class='$cls' title='$sev'>$disp</td>"
        }
        $html += "</tr>"
    }

    $html += @"
    </tbody></table>
    <p class="small">Legend: red=High, yellow=Medium, green=Low, grey=no issues.</p>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
const sev = $sevJson;
const cat = $catJson;

const sevLabels = sev.map(x => x.Severity);
const sevData   = sev.map(x => x.Count);
const catLabels = cat.map(x => x.Category);
const catData   = cat.map(x => x.Count);

new Chart(document.getElementById('sevChart').getContext('2d'), {
  type: 'bar',
  data: { labels: sevLabels, datasets: [{ label: 'Findings', data: sevData }] },
  options: { responsive: true, plugins: { legend: { display: false } } }
});

new Chart(document.getElementById('catChart').getContext('2d'), {
  type: 'pie',
  data: { labels: catLabels, datasets: [{ data: catData }] },
  options: { responsive: true }
});
</script>
</body></html>
"@

    $html | Out-File -FilePath $OutFile -Encoding UTF8
}

# ============= GPO Backups =============
function Backup-SelectiveGPOs {
    param([Parameter(Mandatory)][string]$Path)
    Write-Log "Performing selective GPO backup (Default Domain / Domain Controllers)..."
    $base = Join-Path $Path "Selective"
    New-Item -Path $base -ItemType Directory -Force | Out-Null
    foreach ($name in @("Default Domain Policy","Default Domain Controllers Policy")) {
        try {
            $gpo  = Get-GPO -Name $name -ErrorAction Stop
            $dest = Join-Path $base ($name -replace " ","_")
            Backup-GPO -Guid $gpo.Id -Path $dest -Comment ("Selective backup {0} {1}" -f $name,(Get-Date)) | Out-Null
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::CreateFromDirectory($dest, "$dest.zip")
            Write-Log "Selective backup created: $dest.zip"
        } catch {
            Write-Log "Selective backup error for $name: $_" "WARN"
        }
    }
}

function Backup-AllGPOs {
    param([Parameter(Mandatory)][string]$Path)
    Write-Log "Performing FULL GPO backup to $Path ..."
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
    $bk = Backup-GPO -All -Path $Path -Comment ("Pre-remediation backup {0}" -f (Get-Date))
    $manifest = $bk | Select-Object DisplayName, Id, CreationTime, GpoStatus, DomainName, Owner
    $mf = Join-Path $Path "GPO_Backup_Manifest.json"
    $manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $mf -Encoding UTF8
    Write-Log "Manifest written: $mf"
}

# ============= Safe Remediation =============
function Remediate-DisableSMBv1 { param([string[]]$Hosts)
    foreach ($h in $Hosts) {
        Write-Log "Remediation: disable SMBv1 on $h"
        try {
            Invoke-Command -ComputerName $h -ScriptBlock {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
                $true
            } -ErrorAction Stop -TimeoutSec 30
            Write-Log "OK: SMBv1 disabled on $h"
        } catch { Write-Log "ERROR disabling SMBv1 on $h: $_" "ERROR" }
    }
}

function Remediate-SetLmCompatibility { param([int]$Value=5,[string[]]$DCs)
    foreach ($dc in $DCs) {
        Write-Log "Remediation: set LmCompatibilityLevel=$Value on $dc"
        try {
            Invoke-Command -ComputerName $dc -ScriptBlock {
                param($v) Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value $v -Force
                $true
            } -ArgumentList $Value -ErrorAction Stop
            Write-Log "OK: LmCompatibilityLevel set on $dc"
        } catch { Write-Log "ERROR setting LmCompatibilityLevel on $dc: $_" "ERROR" }
    }
}

function Remediate-EnableRDPNLA { param([string[]]$Hosts)
    foreach ($h in $Hosts) {
        Write-Log "Remediation: enable RDP NLA on $h"
        try {
            Invoke-Command -ComputerName $h -ScriptBlock {
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Force
                $true
            } -ErrorAction Stop -TimeoutSec 20
            Write-Log "OK: NLA enabled on $h"
        } catch { Write-Log "ERROR enabling NLA on $h: $_" "ERROR" }
    }
}

# ============= EXECUTION =============
Write-Log "Starting audit..."
Backup-SelectiveGPOs -Path $BackupPath  # Always safe

$smb         = Audit-SMBv1
$ntlm        = Audit-NTLM
$rdp         = Audit-RDP
$localAdmins = Audit-LocalAdmins
$laps        = Audit-LAPS
$ldap        = Audit-LDAPSigning
$kerb        = Audit-KerberosLifetime

$findings = Build-Findings -smb $smb -ntlm $ntlm -rdp $rdp -localAdmins $localAdmins -laps $laps -ldap $ldap -kerb $kerb
$exports  = Export-Findings -Findings $findings -OutDir $ExportPath

$reportHtml    = Join-Path $ExportPath "report.html"
$dashboardHtml = Join-Path $ExportPath "dashboard.html"
Build-HTMLReport    -Findings $findings -OutFile $reportHtml
Build-HTMLDashboard -Findings $findings -OutFile $dashboardHtml
Write-Log "Generated: $reportHtml ; $dashboardHtml"

Write-Log "Remediation plan (summary):"
$findings | Group-Object -Property Remediation | ForEach-Object {
    Write-Log (" - {0}: {1}" -f $_.Name, $_.Count)
}

if ($Apply) {
    if (-not $Force) {
        $ans = Read-Host "WARNING: remediations will be applied (test in LAB recommended). Proceed? [Y/N]"
        if ($ans -notin @('Y','y','S','s')) { Write-Log "Operation canceled."; exit 1 }
    } else { Write-Log "Apply forced (-Force)." }

    $fullBackup = Join-Path $BackupPath ("GPOBackup_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    Backup-AllGPOs -Path $fullBackup

    $dcsToFix   = $ntlm | Where-Object { $_.LmCompatibilityLevel -is [int] -and $_.LmCompatibilityLevel -lt 5 } | Select-Object -ExpandProperty DC -Unique
    $smbToFix   = $smb  | Where-Object { $_.SMBv1 -and $_.SMBv1 -ne "Disabled" -and $_.SMBv1 -ne "Unreachable" } | Select-Object -ExpandProperty Host -Unique
    $hostsNoNLA = $rdp  | Where-Object { $_.NLA -ne 1 } | Select-Object -ExpandProperty Host -Unique

    if ($dcsToFix)   { Remediate-SetLmCompatibility -Value 5 -DCs $dcsToFix }
    if ($smbToFix)   { Remediate-DisableSMBv1 -Hosts $smbToFix }
    if ($hostsNoNLA) { Remediate-EnableRDPNLA   -Hosts $hostsNoNLA }

    Write-Log "Remediations completed."
} else {
    Write-Log "Dry-run mode: no changes applied. Use -Apply to execute remediations (a full GPO backup will be created first)."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = Join-Path $ExportPath ("ADHardening_{0}.zip" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
[System.IO.Compression.ZipFile]::CreateFromDirectory($ExportPath, $zip)
Write-Log "Final package created: $zip"

Write-Log "Script COMPLETED."
