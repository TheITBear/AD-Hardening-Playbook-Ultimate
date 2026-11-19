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
  AD-Hardening-Playbook-Ultimate.ps1 - Enterprise-grade AD audit + safe remediation.

.DESCRIPTION
  - Performs AD/Windows security checks:
      * SMBv1 (server config + optional feature), SMB signing
      * NTLM (LmCompatibilityLevel) on Domain Controllers
      * RDP NLA / SecurityLayer
      * Domain principals in local Administrators (member servers)
      * LAPS (legacy + Windows LAPS: schema and real coverage)
      * LDAP Signing & Channel Binding (DC)
      * Kerberos ticket lifetime (DDP/DDCP)
  - Remote checks run in PARALLEL (one WinRM fan-out per target class).
  - Generates JSON/CSV/HTML reports and an HTML dashboard (Chart.js + heatmap).
  - Always performs a selective GPO backup (DDP/DDCP); performs a full GPO
    backup before any remediation.
  - Dry-run by default; remediations only with -Apply.

  The file is intentionally pure ASCII: Windows PowerShell 5.1 reads BOM-less
  files as ANSI, and UTF-8 punctuation (e.g. em dash) can break the parser.

.PARAMETER Apply
  Applies safe remediations (a full GPO backup is performed first).

.PARAMETER ExportPath
  Output directory for reports. Default: C:\Temp\ADHardeningReport_YYYYMMDD_HHmmss

.PARAMETER BackupPath
  Root directory for GPO backups. Default: C:\Temp\GPO_Backups

.PARAMETER Force
  Skips the interactive confirmation prompt during Apply.

.PARAMETER VerboseLog
  Prints INFO/DEBUG logs to console (run.log is always written).

.PARAMETER MaxServers
  Max number of member servers to scan (0 = all). Default: 150.

.PARAMETER StaleDays
  Skip computer accounts whose last logon is older than N days (0 = no filter). Default: 90.

.PARAMETER ThrottleLimit
  Max concurrent WinRM connections. Default: 32.

.PARAMETER ConnectTimeoutSec
  WinRM connection (open) timeout per host. Default: 15.

.PARAMETER OperationTimeoutSec
  WinRM operation timeout per host. Default: 120.

.EXAMPLE
  .\AD-Hardening-Playbook-Ultimate.ps1
  .\AD-Hardening-Playbook-Ultimate.ps1 -MaxServers 0 -ThrottleLimit 64 -VerboseLog
  .\AD-Hardening-Playbook-Ultimate.ps1 -Apply -Force
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$Apply,
    [string]$ExportPath = "",
    [string]$BackupPath = "C:\Temp\GPO_Backups",
    [switch]$Force,
    [switch]$VerboseLog,
    [ValidateRange(0, 100000)] [int]$MaxServers = 150,
    [ValidateRange(0, 3650)]   [int]$StaleDays = 90,
    [ValidateRange(1, 512)]    [int]$ThrottleLimit = 32,
    [ValidateRange(1, 600)]    [int]$ConnectTimeoutSec = 15,
    [ValidateRange(5, 3600)]   [int]$OperationTimeoutSec = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$RunStamp = Get-Date -Format "yyyyMMdd_HHmmss"

# ============= Logging & Utilities =============
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")] [string]$Level = "INFO"
    )
    $line = "{0} [{1}] {2}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $Level, $Message
    if ($VerboseLog -or $Level -in @("WARN","ERROR")) { Write-Host $line }
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 }
}

function Import-RequiredModule {
    param([Parameter(Mandatory)] [string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        # ActiveDirectory / GroupPolicy are RSAT components, NOT PowerShell Gallery modules.
        $hint = "Install RSAT (Server: Install-WindowsFeature RSAT-AD-PowerShell,GPMC ; " +
                "Client: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 / " +
                "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0)."
        throw "Module '$Name' not found. $hint"
    }
    Import-Module $Name -ErrorAction Stop
    Write-Log "Module loaded: $Name" "DEBUG"
}

function New-Finding {
    param(
        [string]$Category, [string]$TargetHost, [string]$Issue,
        [ValidateSet("High","Medium","Low")] [string]$Severity, [string]$Remediation
    )
    [pscustomobject]@{
        Category = $Category; Host = $TargetHost; Issue = $Issue
        Severity = $Severity; Remediation = $Remediation
    }
}

function Get-SevScore([string]$s) {
    switch ($s) { "High" { 3 } "Medium" { 2 } "Low" { 1 } default { 0 } }
}

function ConvertTo-HtmlSafe([object]$s) {
    [System.Net.WebUtility]::HtmlEncode([string]$s)
}

# ============= Preflight & Paths =============
if (-not $ExportPath) {
    $ExportPath = Join-Path "C:\Temp" ("ADHardeningReport_{0}" -f $RunStamp)
}
New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
$script:LogFile = Join-Path $ExportPath "run.log"

Write-Log "ExportPath: $ExportPath"
Write-Log "BackupPath: $BackupPath"

Write-Log "Running preflight checks..."
Import-RequiredModule -Name ActiveDirectory
Import-RequiredModule -Name GroupPolicy
try {
    $Domain = Get-ADDomain -ErrorAction Stop
    Write-Log "Domain detected: $($Domain.DNSRoot)"
} catch {
    Write-Log "Unable to query AD domain. Check RSAT/permissions/connectivity: $($_.Exception.Message)" "ERROR"
    throw
}

# ============= Remote execution: parallel fan-out =============
# Invoke-Command has NO -TimeoutSec parameter: timeouts are set via PSSessionOption.
$script:SessionOption = New-PSSessionOption `
    -OpenTimeout ($ConnectTimeoutSec * 1000) `
    -OperationTimeout ($OperationTimeoutSec * 1000) `
    -CancelTimeout 5000

function Invoke-Fanout {
    <#
      Runs one scriptblock on many hosts in parallel (native Invoke-Command fan-out).
      Returns one object per requested host: Host, Reachable, Data, Error.
    #>
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$ComputerName,
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )
    if (-not $ComputerName -or $ComputerName.Count -eq 0) { return @() }

    $errs = $null
    $raw = Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList `
        -SessionOption $script:SessionOption -ThrottleLimit $ThrottleLimit `
        -ErrorAction SilentlyContinue -ErrorVariable errs

    $byHost = @{}
    foreach ($r in @($raw)) {
        if ($null -ne $r -and $r.PSObject.Properties['PSComputerName']) { $byHost[[string]$r.PSComputerName] = $r }
    }
    $errList = @($errs)

    foreach ($h in $ComputerName) {
        if ($byHost.ContainsKey($h)) {
            [pscustomobject]@{ Host = $h; Reachable = $true; Data = $byHost[$h]; Error = $null }
        } else {
            $e = $errList | Where-Object {
                ([string]$_.TargetObject -eq $h) -or ($_.ToString() -match [regex]::Escape($h))
            } | Select-Object -First 1
            $msg = if ($e) { ($e.ToString() -split "`n")[0].Trim() } else { "No response" }
            [pscustomobject]@{ Host = $h; Reachable = $false; Data = $null; Error = $msg }
        }
    }
}

# ============= Inventory =============
function Get-TargetName($c) {
    # Prefer FQDN: helps Kerberos (avoids NTLM fallback on short names / IPs)
    if ($c.DNSHostName) { [string]$c.DNSHostName } else { [string]$c.Name }
}

Write-Log "Building inventory..."
$DCs = @(Get-ADDomainController -Filter * | Sort-Object HostName | ForEach-Object { [string]$_.HostName })
Write-Log ("Domain Controllers: {0}" -f $DCs.Count)

$srvFilter = "OperatingSystem -like '*Server*' -and Enabled -eq 'True'"
$servers = Get-ADComputer -Filter $srvFilter -Properties OperatingSystem, DNSHostName, LastLogonDate, PrimaryGroupID
if ($StaleDays -gt 0) {
    $cut = (Get-Date).AddDays(-$StaleDays)
    $servers = $servers | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -ge $cut }
}
# Exclude DCs (PrimaryGroupID 516 = Domain Controllers, 521 = RODC): they are audited separately
$MemberServers = @($servers | Where-Object { $_.PrimaryGroupID -notin 516, 521 } |
    Sort-Object Name | ForEach-Object { Get-TargetName $_ })
if ($MaxServers -gt 0 -and $MemberServers.Count -gt $MaxServers) {
    Write-Log ("Member servers found: {0}, limited to first {1} (-MaxServers)" -f $MemberServers.Count, $MaxServers) "WARN"
    $MemberServers = @($MemberServers | Select-Object -First $MaxServers)
}
Write-Log ("Member servers in scope: {0}" -f $MemberServers.Count)

# ============= Remote probes =============
# Shared probe (DCs + member servers): SMB, RDP, optional local admins. Runs remotely (no StrictMode there).
$HostProbe = {
    param([bool]$CollectAdmins)
    $o = [ordered]@{ SMB1Server = $null; SMB1Feature = 'NotChecked'; SMBSigningRequired = $null;
                     NLA = $null; SecurityLayer = $null; Admins = @(); AdminsError = $null }

    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        $o.SMB1Server = [bool]$smb.EnableSMB1Protocol
        $o.SMBSigningRequired = [bool]$smb.RequireSecuritySignature
    } catch { }   # Get-SmbServerConfiguration unavailable (e.g. 2008 R2): leave $null

    # DISM query is slow: run it only when SMB1 server side is not already known to be off
    if ($o.SMB1Server -ne $false) {
        try {
            $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
            $o.SMB1Feature = if ($f) { [string]$f.State } else { 'NotPresent' }
        } catch { $o.SMB1Feature = 'Unknown' }
    }

    $rdp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
    if ($rdp) { $o.NLA = $rdp.UserAuthentication; $o.SecurityLayer = $rdp.SecurityLayer }

    if ($CollectAdmins) {
        $me = $env:COMPUTERNAME
        $isDomain = {
            param($name)
            if ($name -notmatch '\\') { return $false }
            $prefix = $name.Split('\')[0]
            -not ($prefix -ieq $me -or $prefix -ieq 'NT AUTHORITY' -or $prefix -ieq 'BUILTIN')
        }
        try {
            # Use well-known SID: works on localized OS (e.g. "Administrateurs")
            $o.Admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_.Name; SID = [string]$_.SID; IsDomain = (& $isDomain ([string]$_.Name)) }
            })
        } catch {
            # Fallback: Get-LocalGroupMember fails with orphaned SIDs / AzureAD members
            try {
                $grpName = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
                $grp = [ADSI]"WinNT://./$grpName,group"
                $o.Admins = @(@($grp.psbase.Invoke('Members')) | ForEach-Object {
                    $path = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
                    $sidB = $_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null)
                    $sid  = try { (New-Object System.Security.Principal.SecurityIdentifier($sidB, 0)).Value } catch { '' }
                    $parts = ($path -replace '^WinNT://', '').Split('/')
                    $name = if ($parts.Count -ge 2) { '{0}\{1}' -f $parts[-2], $parts[-1] } else { $parts[-1] }
                    [pscustomobject]@{ Name = $name; SID = $sid; IsDomain = (& $isDomain $name) }
                })
            } catch { $o.AdminsError = $_.Exception.Message }
        }
    }
    [pscustomobject]$o
}

$DcProbe = {
    $lsa  = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $ntds = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
    [pscustomobject]@{
        LmCompatibilityLevel      = if ($lsa)  { $lsa.LmCompatibilityLevel } else { $null }
        LDAPServerIntegrity       = if ($ntds) { $ntds.LDAPServerIntegrity } else { $null }
        # Correct value name for LDAP Channel Binding is LdapEnforceChannelBinding (0/1/2)
        LdapEnforceChannelBinding = if ($ntds) { $ntds.LdapEnforceChannelBinding } else { $null }
    }
}

# ============= AUDIT: AD-side (no WinRM) =============
function Get-LapsFinding {
    Write-Log "Auditing LAPS (schema + real coverage, legacy and Windows LAPS)..."
    $finds = @()
    try {
        $schemaNC = (Get-ADRootDSE).schemaNamingContext
        $hasLegacy = [bool](Get-ADObject -SearchBase $schemaNC -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)' -ErrorAction SilentlyContinue)
        $hasWin    = [bool](Get-ADObject -SearchBase $schemaNC -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' -ErrorAction SilentlyContinue)
        Write-Log "LAPS schema - Legacy: $hasLegacy ; Windows LAPS: $hasWin" "DEBUG"

        if (-not $hasLegacy -and -not $hasWin) {
            return @(New-Finding -Category "LAPS" -TargetHost "Domain" -Severity "High" `
                -Issue "LAPS schema not extended (neither legacy nor Windows LAPS)" `
                -Remediation "Update-LapsADSchema (Windows LAPS), delegate Set-LapsADComputerSelfPermission, deploy LAPS GPO")
        }

        # Enabled, non-DC computers (UAC 8192 = SERVER_TRUST_ACCOUNT, 2 = ACCOUNTDISABLE)
        $base = '(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        $total = @(Get-ADComputer -LDAPFilter "(&(objectCategory=computer)$base)").Count
        $attrTerms = @()
        if ($hasLegacy) { $attrTerms += '(ms-Mcs-AdmPwdExpirationTime=*)' }
        if ($hasWin)    { $attrTerms += '(msLAPS-PasswordExpirationTime=*)' }
        $managed = @(Get-ADComputer -LDAPFilter ("(&(objectCategory=computer){0}(|{1}))" -f $base, ($attrTerms -join ''))).Count
        $pct = if ($total -gt 0) { [math]::Round(100 * $managed / $total, 1) } else { 100 }
        Write-Log "LAPS coverage: $managed / $total ($pct%)"

        if ($pct -lt 100) {
            $sev = if ($pct -lt 90) { "High" } else { "Medium" }
            $finds += New-Finding -Category "LAPS" -TargetHost "Domain" -Severity $sev `
                -Issue ("LAPS coverage {0}% ({1}/{2} enabled non-DC computers have a managed password)" -f $pct, $managed, $total) `
                -Remediation "Extend LAPS GPO/policy to all OUs; investigate unmanaged and stale computer objects"
        }
    } catch {
        $finds += New-Finding -Category "LAPS" -TargetHost "Domain" -Severity "Low" `
            -Issue "Unable to evaluate LAPS: $($_.Exception.Message)" -Remediation "Check read permissions on schema/computers"
    }
    $finds
}

function Get-KerberosFinding {
    Write-Log "Auditing Kerberos ticket lifetime (Default Domain / Domain Controllers Policies)..."
    # Thresholds = Microsoft defaults. Units: MaxTicketAge h, MaxRenewAge days, MaxServiceAge min. 0 = never expires.
    $limits = [ordered]@{ MaxTicketAge = 10; MaxRenewAge = 7; MaxServiceAge = 600 }
    $finds = @()
    foreach ($gpoName in @("Default Domain Policy", "Default Domain Controllers Policy")) {
        try {
            $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
            [xml]$xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
            foreach ($k in $limits.Keys) {
                # GPO report XML is namespaced: <q1:Account><q1:Name>MaxTicketAge</q1:Name><q1:SettingNumber>
                $xp = "//*[local-name()='Account'][*[local-name()='Name']='$k']/*[local-name()='SettingNumber']"
                $n = $xml.SelectSingleNode($xp)
                if ($n) {
                    $v = [int]$n.InnerText
                    if ($v -eq 0 -or $v -gt $limits[$k]) {
                        $sev = if ($v -eq 0) { "High" } else { "Medium" }
                        $finds += New-Finding -Category "Kerberos" -TargetHost ($gpoName -replace ' ', '') -Severity $sev `
                            -Issue ("{0} = {1} (recommended <= {2}{3})" -f $k, $v, $limits[$k], $(if ($v -eq 0) { ', 0 = never expires' } else { '' })) `
                            -Remediation "Set $k <= $($limits[$k]) (Kerberos policy is effective only from domain-linked GPOs)"
                    }
                }
            }
        } catch {
            $finds += New-Finding -Category "Kerberos" -TargetHost "Domain" -Severity "Low" `
                -Issue "Unable to read '$gpoName': $($_.Exception.Message)" -Remediation "Check GPO read permissions"
        }
    }
    $finds
}

# ============= Findings synthesis =============
function Get-HostFinding {
    param($Results, [bool]$IsDC)
    $f = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Results) {
        if (-not $r.Reachable) {
            $f.Add((New-Finding -Category "Connectivity" -TargetHost $r.Host -Severity $(if ($IsDC) { "Medium" } else { "Low" }) `
                -Issue "WinRM unreachable: $($r.Error)" -Remediation "Verify WinRM (5985/5986), firewall, Kerberos/SPN, permissions"))
            continue
        }
        $d = $r.Data

        if ($d.SMB1Server -eq $true) {
            $f.Add((New-Finding -Category "SMBv1" -TargetHost $r.Host -Severity "High" -Issue "SMBv1 server protocol enabled" `
                -Remediation "Audit SMB1 access (Set-SmbServerConfiguration -AuditSmb1Access), then disable"))
        } elseif ($d.SMB1Feature -eq 'Enabled') {
            $f.Add((New-Finding -Category "SMBv1" -TargetHost $r.Host -Severity "Medium" -Issue "SMB1Protocol optional feature still installed" `
                -Remediation "Disable-WindowsOptionalFeature SMB1Protocol (reboot required)"))
        }
        if ($d.SMBSigningRequired -eq $false) {
            $f.Add((New-Finding -Category "SMBSigning" -TargetHost $r.Host -Severity "Medium" -Issue "SMB server signing not required" `
                -Remediation "GPO: Microsoft network server: Digitally sign communications (always) = Enabled"))
        }
        if ($d.NLA -ne 1) {
            $f.Add((New-Finding -Category "RDP" -TargetHost $r.Host -Severity "Medium" -Issue "RDP NLA not enforced (UserAuthentication=$($d.NLA))" `
                -Remediation "Enable NLA (UserAuthentication=1), preferably via GPO"))
        }
        if (-not $IsDC) {
            if ($d.AdminsError) {
                $f.Add((New-Finding -Category "LocalAdmins" -TargetHost $r.Host -Severity "Low" -Issue "Unable to enumerate local Administrators: $($d.AdminsError)" `
                    -Remediation "Check permissions / orphaned SIDs"))
            }
            foreach ($m in @($d.Admins)) {
                if ($m.SID -match '-512$') { continue }   # Domain Admins: default membership
                if ($m.IsDomain) {
                    $f.Add((New-Finding -Category "LocalAdmins" -TargetHost $r.Host -Severity "Medium" -Issue "Domain principal in local Administrators: $($m.Name)" `
                        -Remediation "Replace with Tier-scoped delegated group (Restricted Groups/GPP) + LAPS"))
                } elseif ($m.Name -match '^S-1-5-21-') {
                    $f.Add((New-Finding -Category "LocalAdmins" -TargetHost $r.Host -Severity "Low" -Issue "Orphaned SID in local Administrators: $($m.Name)" `
                        -Remediation "Remove orphaned SID"))
                }
            }
        }
    }
    $f
}

function Get-DcFinding {
    param($Results)
    $f = [System.Collections.Generic.List[object]]::new()
    foreach ($r in ($Results | Where-Object Reachable)) {
        $d = $r.Data
        $lm = $d.LmCompatibilityLevel
        if ($null -eq $lm -or [int]$lm -lt 5) {
            $shown = if ($null -eq $lm) { "not set (OS default 3)" } else { $lm }
            $f.Add((New-Finding -Category "NTLM" -TargetHost $r.Host -Severity "High" -Issue "LmCompatibilityLevel is $shown" `
                -Remediation "Audit NTLMv1 usage (Event 4624 LmPackageName), then LmCompatibilityLevel=5 via GPO"))
        }
        if ($null -eq $d.LDAPServerIntegrity -or [int]$d.LDAPServerIntegrity -lt 2) {
            $f.Add((New-Finding -Category "LDAP" -TargetHost $r.Host -Severity "High" -Issue "LDAP signing not required (LDAPServerIntegrity=$($d.LDAPServerIntegrity))" `
                -Remediation "Audit Event 2889, then GPO: Domain controller: LDAP server signing requirements = Require signing"))
        }
        $cbt = $d.LdapEnforceChannelBinding
        if ($null -eq $cbt -or [int]$cbt -lt 2) {
            $sev = if ($null -ne $cbt -and [int]$cbt -eq 1) { "Medium" } else { "High" }
            $f.Add((New-Finding -Category "LDAP" -TargetHost $r.Host -Severity $sev -Issue "LDAP channel binding not set to Always (LdapEnforceChannelBinding=$cbt)" `
                -Remediation "Audit Events 3039/3040/3041, then LdapEnforceChannelBinding=2 via GPO"))
        }
    }
    $f
}

# ============= Export & Reporting =============
function Export-Finding {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Findings, [Parameter(Mandatory)] [string]$OutDir)
    $json = Join-Path $OutDir "findings.json"
    $csv  = Join-Path $OutDir "findings.csv"
    # -InputObject keeps a JSON array even with 0/1 elements
    ConvertTo-Json -InputObject @($Findings) -Depth 6 | Out-File -FilePath $json -Encoding UTF8
    if ($Findings.Count) { $Findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 }
    else { "Category,Host,Issue,Severity,Remediation" | Out-File -FilePath $csv -Encoding UTF8 }
    Write-Log "Findings exported: $json ; $csv"
}

function Build-HTMLReport {
    param([AllowEmptyCollection()] [object[]]$Findings, [string]$OutFile)
    $now = Get-Date
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>AD Hardening Report - $now</title>
<style>
body{font-family:Segoe UI,Arial;margin:16px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:6px;font-size:13px}
th{background:#f4f4f4;text-align:left}
.badge{padding:2px 6px;border-radius:4px}
.sev-High{background:#ffdddd;border:1px solid #ff9d9d}
.sev-Medium{background:#fff1cc;border:1px solid #ffd666}
.sev-Low{background:#ddffdd;border:1px solid #9dff9d}
</style></head><body>
<h1>AD Hardening Report</h1>
<p>Domain: $(ConvertTo-HtmlSafe $Domain.DNSRoot) - Generated: $now - Findings: $($Findings.Count)</p>
<table><tr><th>Category</th><th>Host</th><th>Issue</th><th>Severity</th><th>Remediation</th></tr>

"@)
    foreach ($f in ($Findings | Sort-Object @{ e = { Get-SevScore $_.Severity }; Descending = $true }, Category, Host)) {
        [void]$sb.AppendFormat("<tr><td>{0}</td><td>{1}</td><td>{2}</td><td><span class='badge sev-{3}'>{3}</span></td><td>{4}</td></tr>`n",
            (ConvertTo-HtmlSafe $f.Category), (ConvertTo-HtmlSafe $f.Host), (ConvertTo-HtmlSafe $f.Issue),
            (ConvertTo-HtmlSafe $f.Severity), (ConvertTo-HtmlSafe $f.Remediation))
    }
    [void]$sb.Append("</table></body></html>")
    $sb.ToString() | Out-File -FilePath $OutFile -Encoding UTF8
}

function Build-HTMLDashboard {
    param([AllowEmptyCollection()] [object[]]$Findings, [string]$OutFile)

    $bySeverity = @($Findings | Group-Object Severity | ForEach-Object { [pscustomobject]@{ Severity = $_.Name; Count = $_.Count } })
    $byCategory = @($Findings | Group-Object Category | ForEach-Object { [pscustomobject]@{ Category = $_.Name; Count = $_.Count } })
    $cats = @($Findings | ForEach-Object { $_.Category } | Sort-Object -Unique)

    # Single pass: host -> category -> max severity score (O(n) instead of O(hosts*cats*n))
    $matrix = @{}
    foreach ($f in $Findings) {
        if (-not $matrix.ContainsKey($f.Host)) { $matrix[$f.Host] = @{} }
        $s = Get-SevScore $f.Severity
        if (-not $matrix[$f.Host].ContainsKey($f.Category) -or $matrix[$f.Host][$f.Category] -lt $s) { $matrix[$f.Host][$f.Category] = $s }
    }
    $label = @{ 3 = "High"; 2 = "Medium"; 1 = "Low"; 0 = "" }

    $sevJson = ConvertTo-Json -InputObject $bySeverity -Depth 4 -Compress
    $catJson = ConvertTo-Json -InputObject $byCategory -Depth 4 -Compress
    $now = Get-Date

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>AD Hardening Dashboard - $now</title>
<style>
body{font-family:Segoe UI,Arial;margin:16px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:24px}
.card{border:1px solid #ddd;border-radius:8px;padding:12px}
h2{margin:6px 0 12px 0}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #eee;padding:6px}
th{background:#fafafa;text-align:left;position:sticky;top:0}
.heat-L3{background:#ff6b6b}.heat-L2{background:#ffd166}.heat-L1{background:#95e06c}.heat-L0{background:#f3f3f3}
.small{font-size:12px;color:#555}
</style></head><body>
<h1>AD Hardening Dashboard</h1>
<p class="small">Domain: $(ConvertTo-HtmlSafe $Domain.DNSRoot) - Generated: $now</p>
<div class="grid">
  <div class="card"><h2>Severity Distribution</h2><canvas id="sevChart" height="180"></canvas></div>
  <div class="card"><h2>Issues by Category</h2><canvas id="catChart" height="180"></canvas></div>
</div>
<div class="card" style="margin-top:24px;">
  <h2>Heatmap: Host x Category</h2>
  <div style="overflow:auto; max-height:540px; border:1px solid #eee;">
    <table id="heatTable"><thead><tr><th>Host</th>
"@)
    foreach ($c in $cats) { [void]$sb.Append("<th>$(ConvertTo-HtmlSafe $c)</th>") }
    [void]$sb.Append("</tr></thead><tbody>`n")
    foreach ($h in ($matrix.Keys | Sort-Object)) {
        [void]$sb.Append("<tr><td><b>$(ConvertTo-HtmlSafe $h)</b></td>")
        foreach ($c in $cats) {
            $score = if ($matrix[$h].ContainsKey($c)) { $matrix[$h][$c] } else { 0 }
            [void]$sb.AppendFormat("<td class='heat-L{0}'>{1}</td>", $score, $label[$score])
        }
        [void]$sb.Append("</tr>`n")
    }
    [void]$sb.Append(@"
    </tbody></table>
    <p class="small">Legend: red=High, yellow=Medium, green=Low, grey=no issues.</p>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<script>
const sev = $sevJson;
const cat = $catJson;
new Chart(document.getElementById('sevChart'), {
  type: 'bar',
  data: { labels: sev.map(x => x.Severity), datasets: [{ label: 'Findings', data: sev.map(x => x.Count) }] },
  options: { responsive: true, plugins: { legend: { display: false } } }
});
new Chart(document.getElementById('catChart'), {
  type: 'pie',
  data: { labels: cat.map(x => x.Category), datasets: [{ data: cat.map(x => x.Count) }] },
  options: { responsive: true }
});
</script>
</body></html>
"@)
    $sb.ToString() | Out-File -FilePath $OutFile -Encoding UTF8
}

# ============= GPO Backups =============
function Backup-SelectiveGPO {
    param([Parameter(Mandatory)] [string]$Path)
    Write-Log "Performing selective GPO backup (Default Domain / Domain Controllers)..."
    $base = Join-Path $Path ("Selective_{0}" -f $RunStamp)
    foreach ($name in @("Default Domain Policy", "Default Domain Controllers Policy")) {
        try {
            $gpo  = Get-GPO -Name $name -ErrorAction Stop
            $dest = Join-Path $base ($name -replace " ", "_")
            New-Item -Path $dest -ItemType Directory -Force | Out-Null   # Backup-GPO requires an existing folder
            Backup-GPO -Guid $gpo.Id -Path $dest -Comment ("Selective backup {0} {1}" -f $name, (Get-Date)) | Out-Null
            $zip = "$dest.zip"
            if (Test-Path $zip) { Remove-Item $zip -Force }
            [System.IO.Compression.ZipFile]::CreateFromDirectory($dest, $zip)
            Write-Log "Selective backup created: $zip"
        } catch {
            Write-Log "Selective backup error for ${name}: $($_.Exception.Message)" "WARN"
        }
    }
}

function Backup-AllGPO {
    param([Parameter(Mandatory)] [string]$Path)
    Write-Log "Performing FULL GPO backup to $Path ..."
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
    $bk = Backup-GPO -All -Path $Path -Comment ("Pre-remediation backup {0}" -f (Get-Date)) -ErrorAction Stop
    $mf = Join-Path $Path "GPO_Backup_Manifest.json"
    ConvertTo-Json -InputObject @($bk | Select-Object DisplayName, GpoId, Id, CreationTime, DomainName, BackupDirectory) -Depth 4 |
        Out-File -FilePath $mf -Encoding UTF8
    Write-Log ("Full GPO backup: {0} GPOs, manifest {1}" -f @($bk).Count, $mf)
}

# ============= Safe Remediation (parallel) =============
function Invoke-Remediation {
    param([string]$Name, [string[]]$Targets, [scriptblock]$ScriptBlock, [object[]]$ArgumentList = @())
    if (-not $Targets) { return }
    Write-Log ("Remediation '{0}' on {1} host(s): {2}" -f $Name, $Targets.Count, ($Targets -join ', '))
    foreach ($r in (Invoke-Fanout -ComputerName $Targets -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList)) {
        if ($r.Reachable) { Write-Log ("OK: {0} on {1} {2}" -f $Name, $r.Host, [string]$r.Data) }
        else { Write-Log ("ERROR: {0} on {1}: {2}" -f $Name, $r.Host, $r.Error) "ERROR" }
    }
}

$FixSMBv1 = {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop   # immediate, no reboot
    $reboot = $false
    $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($f -and $f.State -eq 'Enabled') {
        $reboot = [bool](Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop).RestartNeeded
    }
    "(RestartNeeded=$reboot)"
}
$FixLmCompat = {
    param($v)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value $v -Type DWord -Force
    "(LmCompatibilityLevel=$v)"
}
$FixNLA = {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord -Force
    "(UserAuthentication=1)"
}

# ============= EXECUTION =============
$sw = [System.Diagnostics.Stopwatch]::StartNew()
Write-Log "Starting audit..."
Backup-SelectiveGPO -Path $BackupPath

# Remote fan-out: 3 parallel batches instead of 5 sequential per-host loops
Write-Log "Remote probe on DCs (registry)..."
$dcReg   = @(Invoke-Fanout -ComputerName $DCs -ScriptBlock $DcProbe)
Write-Log "Remote probe on DCs (SMB/RDP)..."
$dcHost  = @(Invoke-Fanout -ComputerName $DCs -ScriptBlock $HostProbe -ArgumentList $false)
Write-Log "Remote probe on member servers (SMB/RDP/LocalAdmins)..."
$srvHost = @(Invoke-Fanout -ComputerName $MemberServers -ScriptBlock $HostProbe -ArgumentList $true)
Write-Log ("Remote probes completed in {0:N1}s" -f $sw.Elapsed.TotalSeconds)

$findings = [System.Collections.Generic.List[object]]::new()
foreach ($set in @(
        (Get-DcFinding -Results $dcReg),
        (Get-HostFinding -Results $dcHost -IsDC $true),
        (Get-HostFinding -Results $srvHost -IsDC $false),
        (Get-LapsFinding),
        (Get-KerberosFinding))) {
    foreach ($x in @($set)) { if ($null -ne $x) { $findings.Add($x) } }
}
$findingsArr = $findings.ToArray()

Export-Finding -Findings $findingsArr -OutDir $ExportPath
$reportHtml    = Join-Path $ExportPath "report.html"
$dashboardHtml = Join-Path $ExportPath "dashboard.html"
Build-HTMLReport    -Findings $findingsArr -OutFile $reportHtml
Build-HTMLDashboard -Findings $findingsArr -OutFile $dashboardHtml
Write-Log "Generated: $reportHtml ; $dashboardHtml"

Write-Log ("Findings: {0} (High {1}, Medium {2}, Low {3})" -f $findingsArr.Count,
    @($findingsArr | Where-Object Severity -eq 'High').Count,
    @($findingsArr | Where-Object Severity -eq 'Medium').Count,
    @($findingsArr | Where-Object Severity -eq 'Low').Count)
$findingsArr | Group-Object Remediation | ForEach-Object { Write-Log (" - {0}: {1}" -f $_.Name, $_.Count) }

if ($Apply) {
    $allHost   = @($dcHost + $srvHost) | Where-Object Reachable
    $dcsToFix  = @($dcReg | Where-Object { $_.Reachable -and ($null -eq $_.Data.LmCompatibilityLevel -or [int]$_.Data.LmCompatibilityLevel -lt 5) } | ForEach-Object Host)
    $smbToFix  = @($allHost | Where-Object { $_.Data.SMB1Server -eq $true -or $_.Data.SMB1Feature -eq 'Enabled' } | ForEach-Object Host)
    $nlaToFix  = @($allHost | Where-Object { $_.Data.NLA -ne 1 } | ForEach-Object Host)

    Write-Host ("Planned remediations -> LmCompatibilityLevel=5: {0} DC | SMBv1 off: {1} host | NLA on: {2} host" -f $dcsToFix.Count, $smbToFix.Count, $nlaToFix.Count)
    Write-Log "NOTE: registry remediations are overwritten by any GPO that sets the same values. Prefer GPO for persistence." "WARN"

    if (-not $Force) {
        $ans = Read-Host "WARNING: remediations will be applied (test in LAB first). Proceed? [Y/N]"
        if ($ans -notin @('Y','y','S','s')) { Write-Log "Operation canceled."; exit 1 }
    } else { Write-Log "Apply forced (-Force)." }

    Backup-AllGPO -Path (Join-Path $BackupPath ("GPOBackup_{0}" -f $RunStamp))

    Invoke-Remediation -Name "LmCompatibilityLevel=5" -Targets $dcsToFix -ScriptBlock $FixLmCompat -ArgumentList 5
    Invoke-Remediation -Name "Disable SMBv1"          -Targets $smbToFix -ScriptBlock $FixSMBv1
    Invoke-Remediation -Name "Enable RDP NLA"         -Targets $nlaToFix -ScriptBlock $FixNLA
    Write-Log "Remediations completed."
} else {
    Write-Log "Dry-run mode: no changes applied. Use -Apply to execute remediations (a full GPO backup will be created first)."
}

# Zip is created outside the source folder (a zip inside the folder being zipped fails with "file in use"), then moved in.
$zipName = "ADHardening_{0}.zip" -f $RunStamp
$tmpZip  = Join-Path ([System.IO.Path]::GetTempPath()) $zipName
if (Test-Path $tmpZip) { Remove-Item $tmpZip -Force }
Write-Log ("Script COMPLETED in {0:N1}s. Packaging results..." -f $sw.Elapsed.TotalSeconds)
[System.IO.Compression.ZipFile]::CreateFromDirectory($ExportPath, $tmpZip)
Move-Item -Path $tmpZip -Destination (Join-Path $ExportPath $zipName) -Force
Write-Host "Final package: $(Join-Path $ExportPath $zipName)"
