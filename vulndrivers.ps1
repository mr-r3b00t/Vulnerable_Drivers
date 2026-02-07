<#
.SYNOPSIS
    VulnDriverScanner.ps1 - Complete Driver Vulnerability Scanner
    Scans system drivers, checks against LOLDrivers.io database, generates HTML report

.DESCRIPTION
    1. Enumerates all system drivers (.sys files)
    2. Computes SHA256 hashes
    3. Downloads/caches LOLDrivers.io vulnerability database
    4. Cross-references hashes to identify vulnerable/abused drivers
    5. Generates interactive HTML report

.PARAMETER ReportPath
    Output path for HTML report (default: Desktop\DriverSecurityReport.html)

.PARAMETER OnlineCheck
    Force fresh download of LOLDrivers database (default: uses cache if < 24hrs old)

.PARAMETER SkipHashCheck
    Skip SHA256 computation (faster but no vulnerability detection)

.EXAMPLE
    .\VulnDriverScanner.ps1
    .\VulnDriverScanner.ps1 -ReportPath "C:\Reports\Drivers.html" -OnlineCheck
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ReportPath = (Join-Path ([Environment]::GetFolderPath("Desktop")) "DriverSecurityReport.html"),
    [switch]$OnlineCheck,
    [switch]$SkipHashCheck
)

# ============================================================================
# Configuration
# ============================================================================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$LOLDriversUrl = "https://www.loldrivers.io/api/drivers.json"
$CachePath = Join-Path $env:TEMP "loldrivers_cache.json"
$CacheMaxAgeHours = 24

# ============================================================================
# Helper Functions
# ============================================================================

function Get-SafeValue {
    param($Value, [string]$Default = "-")
    try {
        if ($null -eq $Value -or [string]::IsNullOrWhiteSpace($Value.ToString())) { return $Default }
        return $Value.ToString()
    }
    catch { return $Default }
}

function Get-DriverFileInfo {
    param([string]$FilePath)
    
    $info = @{
        Manufacturer = "-"
        ProductName  = "-"
        FileVersion  = "-"
        DriverDate   = "-"
        Description  = "-"
    }
    
    try {
        if (-not (Test-Path -Path $FilePath -PathType Leaf)) { return $info }
        
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
        if ($versionInfo) {
            $info.Manufacturer = Get-SafeValue -Value $versionInfo.CompanyName
            $info.ProductName  = Get-SafeValue -Value $versionInfo.ProductName
            $info.FileVersion  = Get-SafeValue -Value $versionInfo.FileVersion
            $info.Description  = Get-SafeValue -Value $versionInfo.FileDescription
        }
        
        $fileItem = Get-Item -Path $FilePath -ErrorAction SilentlyContinue
        if ($fileItem) { $info.DriverDate = $fileItem.LastWriteTime.ToString("yyyy-MM-dd") }
    }
    catch { }
    
    return $info
}

function ConvertTo-HtmlSafeString {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "-" }
    return $Text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace('"', "&quot;").Replace("'", "&#39;")
}

function Format-FileSize {
    param([long]$Bytes)
    if ($Bytes -le 0) { return "-" }
    if ($Bytes -lt 1KB) { return "$Bytes B" }
    if ($Bytes -lt 1MB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    if ($Bytes -lt 1GB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    return "{0:N2} GB" -f ($Bytes / 1GB)
}

function Get-TruncatedHash {
    param([string]$Hash, [int]$Length = 12)
    if ([string]::IsNullOrWhiteSpace($Hash) -or $Hash.Length -lt $Length) {
        return @{ Short = "-"; Full = "-" }
    }
    return @{ Short = $Hash.Substring(0, $Length) + "..."; Full = $Hash }
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
        return $true
    }
    catch {
        Write-Error ("Failed to write file: " + $_.Exception.Message)
        return $false
    }
}

function Get-FileHashSafe {
    param([string]$FilePath)
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash.ToUpper()
    }
    catch {
        return $null
    }
}

# ============================================================================
# LOLDrivers Database Functions
# ============================================================================

function ConvertFrom-JsonLenient {
    # PS5.1 ConvertFrom-Json fails on duplicate keys (case-insensitive)
    # Use .NET JavaScriptSerializer which overwrites duplicates instead of failing
    param([string]$JsonString)
    
    try {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = [int]::MaxValue
        $result = $serializer.DeserializeObject($JsonString)
        return $result
    }
    catch {
        # Fallback: try standard ConvertFrom-Json
        return (ConvertFrom-Json $JsonString)
    }
}

function Get-LOLDriversDatabase {
    param([bool]$ForceOnline = $false)
    
    $useCache = $false
    
    # Check cache
    if (-not $ForceOnline -and (Test-Path $CachePath)) {
        $cacheFile = Get-Item $CachePath
        $cacheAge = (Get-Date) - $cacheFile.LastWriteTime
        if ($cacheAge.TotalHours -lt $CacheMaxAgeHours) {
            $useCache = $true
            Write-Host "[*] Using cached LOLDrivers database (age: $([math]::Round($cacheAge.TotalHours, 1)) hours)" -ForegroundColor Cyan
        }
    }
    
    if ($useCache) {
        try {
            $jsonContent = Get-Content -Path $CachePath -Raw -ErrorAction Stop
            return (ConvertFrom-JsonLenient $jsonContent)
        }
        catch {
            Write-Warning "Cache corrupted, fetching fresh data..."
            $useCache = $false
        }
    }
    
    # Fetch online
    Write-Host "[*] Downloading LOLDrivers database..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $response = Invoke-WebRequest -Uri $LOLDriversUrl -UseBasicParsing -TimeoutSec 60
        $jsonContent = $response.Content
        
        # Cache it
        $jsonContent | Out-File -FilePath $CachePath -Encoding utf8 -Force
        Write-Host "[+] LOLDrivers database downloaded and cached" -ForegroundColor Green
        
        return (ConvertFrom-JsonLenient $jsonContent)
    }
    catch {
        Write-Warning ("Failed to download LOLDrivers database: " + $_.Exception.Message)
        
        # Try cache as fallback
        if (Test-Path $CachePath) {
            Write-Host "[*] Using stale cache as fallback..." -ForegroundColor Yellow
            $jsonContent = Get-Content -Path $CachePath -Raw
            return (ConvertFrom-JsonLenient $jsonContent)
        }
        
        return $null
    }
}

function Build-HashLookup {
    param($LOLDriversData)
    
    $lookup = @{}
    
    foreach ($driver in $LOLDriversData) {
        
        # Helper to safely get property value from Dictionary or PSObject
        $drvName = $null
        $drvCategory = $null
        $drvDesc = $null
        $drvUsecase = $null
        $drvTags = $null
        $drvId = $null
        $drvSamples = $null
        
        try {
            if ($driver -is [System.Collections.IDictionary]) {
                if ($driver.Keys -contains "Name") { $drvName = $driver["Name"] }
                if ($driver.Keys -contains "Category") { $drvCategory = $driver["Category"] }
                if ($driver.Keys -contains "Description") { $drvDesc = $driver["Description"] }
                if ($driver.Keys -contains "Usecase") { $drvUsecase = $driver["Usecase"] }
                if ($driver.Keys -contains "Tags") { $drvTags = $driver["Tags"] }
                if ($driver.Keys -contains "Id") { $drvId = $driver["Id"] }
                if ($driver.Keys -contains "KnownVulnerableSamples") { $drvSamples = $driver["KnownVulnerableSamples"] }
            }
            else {
                $drvName = $driver.Name
                $drvCategory = $driver.Category
                $drvDesc = $driver.Description
                $drvUsecase = $driver.Usecase
                $drvTags = $driver.Tags
                $drvId = $driver.Id
                $drvSamples = $driver.KnownVulnerableSamples
            }
        }
        catch { continue }
        
        $vulnInfo = @{
            Name        = Get-SafeValue -Value $drvName
            Category    = Get-SafeValue -Value $drvCategory
            Description = Get-SafeValue -Value $drvDesc
            CVE         = "-"
            Usecase     = Get-SafeValue -Value $drvUsecase
            Tags        = ""
            DetailUrl   = ""
        }
        
        # Extract CVEs
        if ($drvSamples) {
            $cves = @()
            foreach ($sample in $drvSamples) {
                try {
                    $sampleCve = $null
                    if ($sample -is [System.Collections.IDictionary]) {
                        if ($sample.Keys -contains "CVE") { $sampleCve = $sample["CVE"] }
                    }
                    else {
                        $sampleCve = $sample.CVE
                    }
                    if ($sampleCve) { $cves += $sampleCve }
                }
                catch { }
            }
            if ($cves.Count -gt 0) { $vulnInfo.CVE = ($cves | Select-Object -Unique) -join ", " }
        }
        
        # Extract tags
        if ($drvTags) {
            if ($drvTags -is [System.Collections.IEnumerable] -and $drvTags -isnot [string]) {
                $vulnInfo.Tags = ($drvTags -join ", ")
            }
            else {
                $vulnInfo.Tags = $drvTags.ToString()
            }
        }
        
        # Build detail URL
        if ($drvId) { $vulnInfo.DetailUrl = "https://www.loldrivers.io/drivers/" + $drvId + "/" }
        
        # Index by all known hashes
        if ($drvSamples) {
            foreach ($sample in $drvSamples) {
                try {
                    $sampleHash = $null
                    if ($sample -is [System.Collections.IDictionary]) {
                        if ($sample.Keys -contains "SHA256") { $sampleHash = $sample["SHA256"] }
                    }
                    else {
                        $sampleHash = $sample.SHA256
                    }
                    if ($sampleHash) {
                        $hashKey = $sampleHash.ToString().ToUpper()
                        $lookup[$hashKey] = $vulnInfo
                    }
                }
                catch { }
            }
        }
    }
    
    Write-Host ("[+] Indexed " + $lookup.Count + " vulnerable driver hashes") -ForegroundColor Green
    return $lookup
}

# ============================================================================
# Driver Enumeration
# ============================================================================

function Get-SystemDrivers {
    Write-Host "[*] Enumerating system drivers..." -ForegroundColor Cyan
    
    $drivers = @()
    
    # Get driver services
    $driverServices = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue
    $serviceMap = @{}
    foreach ($svc in $driverServices) {
        if ($svc.PathName) {
            $cleanPath = $svc.PathName -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot
            $cleanPath = [System.Environment]::ExpandEnvironmentVariables($cleanPath)
            $serviceMap[$cleanPath.ToLower()] = $svc
        }
    }
    
    # Scan driver directories
    $driverPaths = @(
        "$env:SystemRoot\System32\drivers",
        "$env:SystemRoot\System32\DriverStore\FileRepository"
    )
    
    $sysFiles = @()
    foreach ($path in $driverPaths) {
        if (Test-Path $path) {
            $sysFiles += Get-ChildItem -Path $path -Filter "*.sys" -Recurse -ErrorAction SilentlyContinue
        }
    }
    
    $total = $sysFiles.Count
    $current = 0
    
    Write-Host "[*] Found $total driver files to analyze" -ForegroundColor Cyan
    
    foreach ($file in $sysFiles) {
        $current++
        if ($current % 50 -eq 0) {
            Write-Progress -Activity "Analyzing drivers" -Status "$current of $total" -PercentComplete (($current / $total) * 100)
        }
        
        $svcInfo = $serviceMap[$file.FullName.ToLower()]
        
        $drvObj = [PSCustomObject]@{
            Name     = $file.Name
            FullName = $file.FullName
            Length   = $file.Length
            SHA256   = $null
            Loaded   = $false
            State    = "-"
            Risk     = "OK"
            VulnInfo = $null
        }
        
        if ($svcInfo) {
            $drvObj.Loaded = ($svcInfo.State -eq "Running")
            $drvObj.State = $svcInfo.State
        }
        
        $drivers += $drvObj
    }
    
    Write-Progress -Activity "Analyzing drivers" -Completed
    Write-Host ("[+] Enumerated " + $drivers.Count + " drivers") -ForegroundColor Green
    
    return $drivers
}

function Add-DriverHashes {
    param([array]$Drivers)
    
    Write-Host "[*] Computing SHA256 hashes (this may take a while)..." -ForegroundColor Cyan
    
    $total = $Drivers.Count
    $current = 0
    
    foreach ($drv in $Drivers) {
        $current++
        if ($current % 25 -eq 0) {
            Write-Progress -Activity "Computing hashes" -Status "$current of $total" -PercentComplete (($current / $total) * 100)
        }
        
        $drv.SHA256 = Get-FileHashSafe -FilePath $drv.FullName
    }
    
    Write-Progress -Activity "Computing hashes" -Completed
    
    $hashedCount = ($Drivers | Where-Object { $_.SHA256 }).Count
    Write-Host ("[+] Computed " + $hashedCount + " hashes") -ForegroundColor Green
}

function Find-VulnerableDrivers {
    param([array]$Drivers, [hashtable]$HashLookup)
    
    Write-Host "[*] Checking drivers against LOLDrivers database..." -ForegroundColor Cyan
    
    $vulnerable = @()
    
    foreach ($drv in $Drivers) {
        if ($drv.SHA256 -and $HashLookup.ContainsKey($drv.SHA256)) {
            $drv.Risk = "VULNERABLE"
            $drv.VulnInfo = $HashLookup[$drv.SHA256]
            $vulnerable += $drv
        }
    }
    
    if ($vulnerable.Count -gt 0) {
        Write-Host ("[!] ALERT: Found " + $vulnerable.Count + " vulnerable driver(s)!") -ForegroundColor Red
    }
    else {
        Write-Host "[+] No known vulnerable drivers detected" -ForegroundColor Green
    }
    
    return $vulnerable
}

# ============================================================================
# Report Generation
# ============================================================================

function New-DriverSecurityReport {
    param(
        [array]$AllDrivers,
        [array]$Vulnerable,
        [string]$ReportPath,
        [bool]$OnlineCheck
    )
    
    $totalCount  = $AllDrivers.Count
    $vulnCount   = $Vulnerable.Count
    $okCount     = $totalCount - $vulnCount
    $loadedCount = @($AllDrivers | Where-Object { $_.Loaded -eq $true }).Count
    $date        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $dataSource  = if ($OnlineCheck) { "Live fetch" } else { "Cached data" }
    $riskLevel   = if ($vulnCount -gt 5) { "CRITICAL" } elseif ($vulnCount -gt 0) { "WARNING" } else { "CLEAN" }
    $riskClass   = $riskLevel.ToLower()
    
    $riskMessage = "No known vulnerable drivers detected on this system"
    if ($riskLevel -eq "CRITICAL") { $riskMessage = "Multiple vulnerable drivers detected requiring immediate attention" }
    if ($riskLevel -eq "WARNING") { $riskMessage = "Vulnerable driver(s) detected - review recommended" }

    $sb = New-Object System.Text.StringBuilder(65536)
    
    # HTML Header
    [void]$sb.Append('<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Driver Security Report - ')
    [void]$sb.Append($date)
    [void]$sb.Append('</title>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0e17; --bg-secondary: #111827; --bg-tertiary: #1f2937;
            --bg-card: #151d2e; --border-color: #2d3748; --border-highlight: #3b82f6;
            --text-primary: #f1f5f9; --text-secondary: #94a3b8; --text-muted: #64748b;
            --accent-blue: #3b82f6; --accent-cyan: #06b6d4; --accent-green: #10b981;
            --accent-yellow: #f59e0b; --accent-red: #ef4444; --accent-purple: #8b5cf6;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Inter, sans-serif; background: var(--bg-primary); color: var(--text-primary); line-height: 1.6; }
        body::before {
            content: ""; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background-image: linear-gradient(rgba(59,130,246,0.03) 1px, transparent 1px),
                              linear-gradient(90deg, rgba(59,130,246,0.03) 1px, transparent 1px);
            background-size: 50px 50px; pointer-events: none; z-index: -1;
        }
        .container { max-width: 1600px; margin: 0 auto; padding: 2rem; }
        header { background: linear-gradient(90deg, #1e3a5f, #0f172a); border: 1px solid var(--border-color); border-radius: 12px; padding: 2rem; margin-bottom: 2rem; }
        .header-content { display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1rem; }
        .logo-section h1 { font-size: 1.75rem; font-weight: 700; margin-bottom: 0.5rem; }
        .logo-section .subtitle { color: var(--text-secondary); font-size: 0.9rem; }
        .meta-info { text-align: right; font-size: 0.85rem; color: var(--text-secondary); }
        .meta-info .timestamp { font-family: "JetBrains Mono", monospace; color: var(--accent-cyan); }
        .risk-banner { display: flex; align-items: center; gap: 1rem; padding: 1rem 1.5rem; border-radius: 8px; margin-bottom: 2rem; border: 1px solid; }
        .risk-banner.critical { background: linear-gradient(135deg, rgba(239,68,68,0.15), rgba(153,27,27,0.1)); border-color: rgba(239,68,68,0.3); }
        .risk-banner.warning { background: linear-gradient(135deg, rgba(245,158,11,0.15), rgba(180,83,9,0.1)); border-color: rgba(245,158,11,0.3); }
        .risk-banner.clean { background: linear-gradient(135deg, rgba(16,185,129,0.15), rgba(4,120,87,0.1)); border-color: rgba(16,185,129,0.3); }
        .risk-indicator { width: 12px; height: 12px; border-radius: 50%; animation: pulse 2s infinite; }
        .risk-indicator.critical { background: var(--accent-red); box-shadow: 0 0 10px var(--accent-red); }
        .risk-indicator.warning { background: var(--accent-yellow); box-shadow: 0 0 10px var(--accent-yellow); }
        .risk-indicator.clean { background: var(--accent-green); box-shadow: 0 0 10px var(--accent-green); }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
        .risk-text { flex: 1; }
        .risk-text strong { display: block; margin-bottom: 0.25rem; }
        .risk-text small { color: var(--text-secondary); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px; padding: 1.25rem; position: relative; }
        .stat-card::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px; border-radius: 10px 10px 0 0; }
        .stat-card.total::before { background: var(--accent-blue); }
        .stat-card.vulnerable::before { background: var(--accent-red); }
        .stat-card.safe::before { background: var(--accent-green); }
        .stat-card.loaded::before { background: var(--accent-purple); }
        .stat-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); margin-bottom: 0.5rem; }
        .stat-value { font-size: 2rem; font-weight: 700; font-family: "JetBrains Mono", monospace; }
        .stat-card.total .stat-value { color: var(--accent-blue); }
        .stat-card.vulnerable .stat-value { color: var(--accent-red); }
        .stat-card.safe .stat-value { color: var(--accent-green); }
        .stat-card.loaded .stat-value { color: var(--accent-purple); }
        .section-header { display: flex; align-items: center; gap: 0.75rem; margin: 2.5rem 0 1.25rem; padding-bottom: 0.75rem; border-bottom: 1px solid var(--border-color); }
        .section-header h2 { font-size: 1.25rem; font-weight: 600; }
        .section-icon { width: 32px; height: 32px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: bold; }
        .section-icon.alert { background: rgba(239,68,68,0.2); color: var(--accent-red); }
        .section-icon.list { background: rgba(59,130,246,0.2); color: var(--accent-blue); }
        .section-icon.info { background: rgba(16,185,129,0.2); color: var(--accent-green); }
        .table-container { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; padding: 1.5rem; overflow-x: auto; }
        table.dataTable { width: 100% !important; border-collapse: separate; border-spacing: 0; font-size: 0.875rem; }
        table.dataTable thead th { background: var(--bg-tertiary); color: var(--text-secondary); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; padding: 1rem 0.75rem; border-bottom: 2px solid var(--border-color); white-space: nowrap; }
        table.dataTable tbody td { padding: 0.875rem 0.75rem; border-bottom: 1px solid var(--border-color); color: var(--text-primary); vertical-align: middle; }
        table.dataTable tbody tr { background: transparent; }
        table.dataTable tbody tr:hover { background: rgba(59,130,246,0.05); }
        table.dataTable tbody tr.vuln-row { background: rgba(239,68,68,0.08); }
        table.dataTable tbody tr.vuln-row:hover { background: rgba(239,68,68,0.12); }
        .dataTables_wrapper { color: var(--text-secondary); }
        .dataTables_filter input, .dataTables_length select { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-primary); padding: 0.5rem; margin-left: 0.5rem; }
        .dataTables_paginate .paginate_button { background: var(--bg-secondary) !important; border: 1px solid var(--border-color) !important; color: var(--text-secondary) !important; border-radius: 6px !important; padding: 0.4rem 0.8rem !important; margin: 0 2px !important; }
        .dataTables_paginate .paginate_button:hover { background: var(--bg-tertiary) !important; color: var(--text-primary) !important; }
        .dataTables_paginate .paginate_button.current { background: var(--accent-blue) !important; color: white !important; }
        .badge { display: inline-flex; padding: 0.3rem 0.65rem; border-radius: 6px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .badge-vuln { background: rgba(239,68,68,0.2); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); }
        .badge-ok { background: rgba(16,185,129,0.2); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.3); }
        .badge-loaded { background: rgba(139,92,246,0.2); color: #c4b5fd; border: 1px solid rgba(139,92,246,0.3); }
        .badge-stopped { background: rgba(100,116,139,0.2); color: #94a3b8; border: 1px solid rgba(100,116,139,0.3); }
        .hash-cell { font-family: "JetBrains Mono", monospace; font-size: 0.8rem; color: var(--accent-cyan); cursor: pointer; }
        .hash-cell:hover { text-decoration: underline; }
        .path-cell { font-family: "JetBrains Mono", monospace; font-size: 0.8rem; color: var(--text-secondary); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .vuln-info { max-width: 250px; }
        .vuln-info .desc { color: var(--text-primary); margin-bottom: 0.35rem; }
        .vuln-info .meta { font-size: 0.75rem; color: var(--text-muted); }
        .cve-link { color: var(--accent-yellow); font-weight: 600; text-decoration: none; }
        .cve-link:hover { text-decoration: underline; }
        a.detail-link { color: var(--accent-blue); text-decoration: none; font-weight: 500; }
        a.detail-link:hover { text-decoration: underline; }
        .recommendations { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; padding: 1.5rem; }
        .recommendations ul { list-style: none; display: grid; gap: 0.75rem; }
        .recommendations li { padding: 0.75rem 1rem; background: var(--bg-secondary); border-radius: 8px; border-left: 3px solid var(--accent-blue); }
        .recommendations a { color: var(--accent-cyan); }
        footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border-color); text-align: center; color: var(--text-muted); font-size: 0.85rem; }
        footer a { color: var(--accent-blue); }
        @media (max-width: 768px) { .header-content { flex-direction: column; } .meta-info { text-align: left; } .stats-grid { grid-template-columns: repeat(2, 1fr); } }
        .export-buttons { display: flex; gap: 0.5rem; margin-top: 1rem; }
        .btn-export { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.5rem 1rem; border-radius: 6px; font-size: 0.8rem; font-weight: 600; cursor: pointer; border: 1px solid; transition: all 0.2s; text-decoration: none; }
        .btn-export.json { background: rgba(16,185,129,0.15); border-color: rgba(16,185,129,0.3); color: #6ee7b7; }
        .btn-export.json:hover { background: rgba(16,185,129,0.25); }
        .btn-export.csv { background: rgba(59,130,246,0.15); border-color: rgba(59,130,246,0.3); color: #93c5fd; }
        .btn-export.csv:hover { background: rgba(59,130,246,0.25); }
        .btn-export.vuln { background: rgba(239,68,68,0.15); border-color: rgba(239,68,68,0.3); color: #fca5a5; }
        .btn-export.vuln:hover { background: rgba(239,68,68,0.25); }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div class="header-content">
            <div class="logo-section">
                <h1>[=] Driver Security Analysis</h1>
                <div class="subtitle">LOLDrivers.io Vulnerability Assessment Report</div>
            </div>
            <div class="meta-info">
                <div>Generated: <span class="timestamp">')
    [void]$sb.Append($date)
    [void]$sb.Append('</span></div>
                <div>Data Source: ')
    [void]$sb.Append($dataSource)
    [void]$sb.Append('</div>
                <div class="export-buttons">
                    <button class="btn-export json" onclick="exportJSON(false)">[JSON] All Drivers</button>
                    <button class="btn-export vuln" onclick="exportJSON(true)">[JSON] Vulnerable Only</button>
                    <button class="btn-export csv" onclick="exportCSV()">[CSV] Export</button>
                </div>
            </div>
        </div>
    </header>

    <div class="risk-banner ')
    [void]$sb.Append($riskClass)
    [void]$sb.Append('">
        <div class="risk-indicator ')
    [void]$sb.Append($riskClass)
    [void]$sb.Append('"></div>
        <div class="risk-text">
            <strong>System Risk Level: ')
    [void]$sb.Append($riskLevel)
    [void]$sb.Append('</strong>
            <small>')
    [void]$sb.Append($riskMessage)
    [void]$sb.Append('</small>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card total"><div class="stat-label">Total Drivers</div><div class="stat-value">')
    [void]$sb.Append($totalCount)
    [void]$sb.Append('</div></div>
        <div class="stat-card vulnerable"><div class="stat-label">Vulnerable</div><div class="stat-value">')
    [void]$sb.Append($vulnCount)
    [void]$sb.Append('</div></div>
        <div class="stat-card safe"><div class="stat-label">Clean</div><div class="stat-value">')
    [void]$sb.Append($okCount)
    [void]$sb.Append('</div></div>
        <div class="stat-card loaded"><div class="stat-label">Loaded</div><div class="stat-value">')
    [void]$sb.Append($loadedCount)
    [void]$sb.Append('</div></div>
    </div>
')

    # Vulnerable Drivers Table
    if ($vulnCount -gt 0) {
        [void]$sb.Append('
    <div class="section-header">
        <div class="section-icon alert">[!]</div>
        <h2>Known Vulnerable Drivers (')
        [void]$sb.Append($vulnCount)
        [void]$sb.Append(')</h2>
    </div>
    <div class="table-container">
        <table id="vulnTable" class="display">
            <thead><tr>
                <th>Driver Name</th><th>Manufacturer</th><th>Version</th><th>Date</th>
                <th>Path</th><th>Size</th><th>SHA256</th><th>Status</th>
                <th>Category</th><th>Vulnerability Info</th><th>Details</th>
            </tr></thead>
            <tbody>
')
        foreach ($drv in $Vulnerable) {
            try {
                $fi = Get-DriverFileInfo -FilePath $drv.FullName
                $sz = Format-FileSize -Bytes $drv.Length
                $hd = Get-TruncatedHash -Hash $drv.SHA256
                $lb = if ($drv.Loaded) { "<span class='badge badge-loaded'>Loaded</span>" } else { "<span class='badge badge-stopped'>Stopped</span>" }
                
                $vi = $drv.VulnInfo
                $desc = $vi.Description
                if ($desc.Length -gt 100) { $desc = $desc.Substring(0, 97) + "..." }
                $desc = ConvertTo-HtmlSafeString -Text $desc
                
                $cve = ""
                if ($vi.CVE -and $vi.CVE -ne "-") {
                    $fc = $vi.CVE.Split(',')[0].Trim()
                    $cve = "<a class='cve-link' href='https://nvd.nist.gov/vuln/detail/" + $fc + "' target='_blank'>" + $vi.CVE + "</a> | "
                }
                
                $dl = if ($vi.DetailUrl) { "<a class='detail-link' href='" + $vi.DetailUrl + "' target='_blank'>View</a>" } else { "-" }
                
                [void]$sb.Append("            <tr class='vuln-row'>
                <td><strong>" + (ConvertTo-HtmlSafeString $drv.Name) + "</strong></td>
                <td>" + $fi.Manufacturer + "</td><td>" + $fi.FileVersion + "</td><td>" + $fi.DriverDate + "</td>
                <td class='path-cell' title='" + (ConvertTo-HtmlSafeString $drv.FullName) + "'>" + (ConvertTo-HtmlSafeString $drv.FullName) + "</td>
                <td>" + $sz + "</td>
                <td class='hash-cell' data-full='" + $hd.Full + "'>" + $hd.Short + "</td>
                <td>" + $lb + "</td>
                <td>" + (ConvertTo-HtmlSafeString $vi.Category) + "</td>
                <td class='vuln-info'><div class='desc'>" + $desc + "</div><div class='meta'>" + $cve + "Usecase: " + (ConvertTo-HtmlSafeString $vi.Usecase) + "</div></td>
                <td>" + $dl + "</td>
            </tr>
")
            } catch { }
        }
        [void]$sb.Append('            </tbody>
        </table>
    </div>
')
    }

    # All Drivers Table
    [void]$sb.Append('
    <div class="section-header">
        <div class="section-icon list">[#]</div>
        <h2>All Drivers (')
    [void]$sb.Append($totalCount)
    [void]$sb.Append(')</h2>
    </div>
    <div class="table-container">
        <table id="allDriversTable" class="display">
            <thead><tr>
                <th>Driver Name</th><th>Manufacturer</th><th>Version</th><th>Date</th>
                <th>Path</th><th>Size</th><th>SHA256</th><th>Status</th><th>Risk</th>
            </tr></thead>
            <tbody>
')

    foreach ($drv in $AllDrivers) {
        try {
            $fi = Get-DriverFileInfo -FilePath $drv.FullName
            $sz = Format-FileSize -Bytes $drv.Length
            $hd = Get-TruncatedHash -Hash $drv.SHA256
            $lb = if ($drv.Loaded) { "<span class='badge badge-loaded'>Loaded</span>" } else { "<span class='badge badge-stopped'>Stopped</span>" }
            $rb = if ($drv.Risk -eq "VULNERABLE") { "<span class='badge badge-vuln'>[!] Vuln</span>" } else { "<span class='badge badge-ok'>[OK]</span>" }
            $rc = if ($drv.Risk -eq "VULNERABLE") { "vuln-row" } else { "" }
            
            [void]$sb.Append("            <tr class='" + $rc + "'>
                <td><strong>" + (ConvertTo-HtmlSafeString $drv.Name) + "</strong></td>
                <td>" + $fi.Manufacturer + "</td><td>" + $fi.FileVersion + "</td><td>" + $fi.DriverDate + "</td>
                <td class='path-cell' title='" + (ConvertTo-HtmlSafeString $drv.FullName) + "'>" + (ConvertTo-HtmlSafeString $drv.FullName) + "</td>
                <td>" + $sz + "</td>
                <td class='hash-cell' data-full='" + $hd.Full + "'>" + $hd.Short + "</td>
                <td>" + $lb + "</td>
                <td>" + $rb + "</td>
            </tr>
")
        } catch { }
    }

    [void]$sb.Append('            </tbody>
        </table>
    </div>

    <div class="section-header">
        <div class="section-icon info">[i]</div>
        <h2>Recommendations</h2>
    </div>
    <div class="recommendations">
        <ul>
            <li>Verify flagged drivers on <a href="https://www.loldrivers.io" target="_blank">loldrivers.io</a></li>
            <li>Enable <strong>Microsoft Vulnerable Driver Block List</strong> (Windows Security &gt; Device Security &gt; Core Isolation)</li>
            <li>Activate <strong>Memory Integrity (HVCI)</strong> if hardware supports it</li>
            <li>Monitor driver loads via <strong>Sysmon Event ID 6</strong></li>
            <li>Deploy <strong>WDAC policies</strong> to block vulnerable driver hashes</li>
        </ul>
    </div>

    <footer>
        <p>Generated using LOLDrivers.io threat intelligence</p>
        <p><a href="https://www.loldrivers.io" target="_blank">LOLDrivers</a> | <a href="https://attack.mitre.org/techniques/T1068/" target="_blank">MITRE T1068</a></p>
    </footer>
</div>

<script>
var reportData = {
    metadata: {
        generated: "')
    [void]$sb.Append($date)
    [void]$sb.Append('",
        dataSource: "')
    [void]$sb.Append($dataSource)
    [void]$sb.Append('",
        riskLevel: "')
    [void]$sb.Append($riskLevel)
    [void]$sb.Append('",
        hostname: "')
    [void]$sb.Append($env:COMPUTERNAME)
    [void]$sb.Append('",
        totalDrivers: ')
    [void]$sb.Append($totalCount)
    [void]$sb.Append(',
        vulnerableCount: ')
    [void]$sb.Append($vulnCount)
    [void]$sb.Append(',
        cleanCount: ')
    [void]$sb.Append($okCount)
    [void]$sb.Append(',
        loadedCount: ')
    [void]$sb.Append($loadedCount)
    [void]$sb.Append('
    },
    drivers: [')
    
    # Build JSON array for all drivers
    $driverJsonItems = @()
    foreach ($drv in $AllDrivers) {
        try {
            $fi = Get-DriverFileInfo -FilePath $drv.FullName
            $isVuln = ($drv.Risk -eq "VULNERABLE")
            
            $jsonObj = @{
                name = $drv.Name
                path = $drv.FullName
                size = $drv.Length
                sha256 = if ($drv.SHA256) { $drv.SHA256 } else { "" }
                loaded = $drv.Loaded
                state = $drv.State
                risk = $drv.Risk
                manufacturer = $fi.Manufacturer
                version = $fi.FileVersion
                date = $fi.DriverDate
                vulnerable = $isVuln
            }
            
            if ($isVuln -and $drv.VulnInfo) {
                $jsonObj.vulnerability = @{
                    category = $drv.VulnInfo.Category
                    description = $drv.VulnInfo.Description
                    cve = $drv.VulnInfo.CVE
                    usecase = $drv.VulnInfo.Usecase
                    detailUrl = $drv.VulnInfo.DetailUrl
                }
            }
            
            # Manual JSON building to avoid encoding issues
            $jsonStr = "{"
            $jsonStr += '"name":"' + ($drv.Name -replace '\\', '\\' -replace '"', '\"') + '",'
            $jsonStr += '"path":"' + ($drv.FullName -replace '\\', '\\\\' -replace '"', '\"') + '",'
            $jsonStr += '"size":' + $drv.Length + ','
            $jsonStr += '"sha256":"' + $(if ($drv.SHA256) { $drv.SHA256 } else { "" }) + '",'
            $jsonStr += '"loaded":' + $(if ($drv.Loaded) { "true" } else { "false" }) + ','
            $jsonStr += '"state":"' + $drv.State + '",'
            $jsonStr += '"risk":"' + $drv.Risk + '",'
            $jsonStr += '"manufacturer":"' + ($fi.Manufacturer -replace '\\', '\\\\' -replace '"', '\"') + '",'
            $jsonStr += '"version":"' + ($fi.FileVersion -replace '\\', '\\\\' -replace '"', '\"') + '",'
            $jsonStr += '"date":"' + $fi.DriverDate + '",'
            $jsonStr += '"vulnerable":' + $(if ($isVuln) { "true" } else { "false" })
            
            if ($isVuln -and $drv.VulnInfo) {
                $jsonStr += ',"vulnerability":{'
                $jsonStr += '"category":"' + ($drv.VulnInfo.Category -replace '\\', '\\\\' -replace '"', '\"') + '",'
                $jsonStr += '"description":"' + ($drv.VulnInfo.Description -replace '\\', '\\\\' -replace '"', '\"' -replace "`r", '' -replace "`n", ' ') + '",'
                $jsonStr += '"cve":"' + $drv.VulnInfo.CVE + '",'
                $jsonStr += '"usecase":"' + ($drv.VulnInfo.Usecase -replace '\\', '\\\\' -replace '"', '\"') + '",'
                $jsonStr += '"detailUrl":"' + $drv.VulnInfo.DetailUrl + '"'
                $jsonStr += '}'
            }
            
            $jsonStr += "}"
            $driverJsonItems += $jsonStr
        }
        catch { }
    }
    
    [void]$sb.Append(($driverJsonItems -join ",`n"))
    [void]$sb.Append('
    ]
};

function exportJSON(vulnOnly) {
    var data = JSON.parse(JSON.stringify(reportData));
    if (vulnOnly) {
        data.drivers = data.drivers.filter(function(d) { return d.vulnerable === true; });
        data.metadata.exportType = "vulnerable_only";
    } else {
        data.metadata.exportType = "all_drivers";
    }
    var blob = new Blob([JSON.stringify(data, null, 2)], {type: "application/json"});
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    var fn = "driver_scan_" + data.metadata.hostname + "_" + new Date().toISOString().slice(0,10);
    a.download = vulnOnly ? fn + "_vulnerable.json" : fn + "_all.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function escapeCSV(str) {
    if (str === null || str === undefined) return "";
    var s = String(str);
    if (s.indexOf(",") > -1 || s.indexOf(Chr(34)) > -1 || s.indexOf(Chr(10)) > -1) {
        return Chr(34) + s.split(Chr(34)).join(Chr(34)+Chr(34)) + Chr(34);
    }
    return s;
}
function Chr(n) { return String.fromCharCode(n); }

function exportCSV() {
    var q = Chr(34);
    var headers = ["Name","Path","Size","SHA256","Loaded","State","Risk","Manufacturer","Version","Date","Vulnerable","Category","CVE","Description"];
    var rows = [headers.join(",")];
    reportData.drivers.forEach(function(d) {
        var row = [
            escapeCSV(d.name),
            escapeCSV(d.path),
            d.size || 0,
            escapeCSV(d.sha256),
            d.loaded ? "Yes" : "No",
            escapeCSV(d.state),
            escapeCSV(d.risk),
            escapeCSV(d.manufacturer),
            escapeCSV(d.version),
            escapeCSV(d.date),
            d.vulnerable ? "Yes" : "No",
            escapeCSV(d.vulnerability ? d.vulnerability.category : ""),
            escapeCSV(d.vulnerability ? d.vulnerability.cve : ""),
            escapeCSV(d.vulnerability ? d.vulnerability.description : "")
        ];
        rows.push(row.join(","));
    });
    var blob = new Blob([rows.join(Chr(10))], {type: "text/csv;charset=utf-8;"});
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "driver_scan_" + reportData.metadata.hostname + "_" + new Date().toISOString().slice(0,10) + ".csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

jQuery(document).ready(function() {
    var cfg = { pageLength: 25, lengthMenu: [[10,25,50,-1],[10,25,50,"All"]], order: [[0,"asc"]], columnDefs: [{targets:6,orderable:false}] };
    if (jQuery("#vulnTable").length) { jQuery("#vulnTable").DataTable({pageLength:10,order:[[0,"asc"]],columnDefs:[{targets:[6,9,10],orderable:false}]}); }
    jQuery("#allDriversTable").DataTable(cfg);
    jQuery(".hash-cell").on("click", function() {
        var h = jQuery(this).data("full"), el = jQuery(this), o = el.text();
        if (h && h !== "-") {
            if (navigator.clipboard) { navigator.clipboard.writeText(h).then(function() { el.text("Copied!"); setTimeout(function(){el.text(o);},1000); }); }
            else { var t=document.createElement("textarea"); t.value=h; document.body.appendChild(t); t.select(); document.execCommand("copy"); document.body.removeChild(t); el.text("Copied!"); setTimeout(function(){el.text(o);},1000); }
        }
    });
});
</script>
</body></html>')

    $result = Write-Utf8NoBom -Path $ReportPath -Content $sb.ToString()
    return $result
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Driver Vulnerability Scanner v1.0" -ForegroundColor Cyan
Write-Host "  LOLDrivers.io Integration" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Get LOLDrivers database
$lolData = Get-LOLDriversDatabase -ForceOnline:$OnlineCheck
if (-not $lolData) {
    Write-Error "Cannot proceed without LOLDrivers database"
    exit 1
}

# Step 2: Build hash lookup
$hashLookup = Build-HashLookup -LOLDriversData $lolData

# Step 3: Enumerate drivers
$allDrivers = Get-SystemDrivers

# Step 4: Compute hashes (unless skipped)
if (-not $SkipHashCheck) {
    Add-DriverHashes -Drivers $allDrivers
}

# Step 5: Find vulnerable drivers
$vulnerable = @()
if (-not $SkipHashCheck) {
    $vulnerable = Find-VulnerableDrivers -Drivers $allDrivers -HashLookup $hashLookup
}

# Step 6: Generate report
Write-Host ""
Write-Host "[*] Generating HTML report..." -ForegroundColor Cyan
$reportResult = New-DriverSecurityReport -AllDrivers $allDrivers -Vulnerable $vulnerable -ReportPath $ReportPath -OnlineCheck:$OnlineCheck

if ($reportResult) {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "  Scan Complete!" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Report saved to: $ReportPath" -ForegroundColor White
    Write-Host ""
    
    # Open report
    if (Test-Path $ReportPath) {
        Write-Host "Opening report in browser..." -ForegroundColor Cyan
        Start-Process $ReportPath
    }
}
else {
    Write-Error "Failed to generate report"
    exit 1
}
