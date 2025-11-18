<#
 FULL FORENSICS IOC TOOLKIT (Single Script + HTML Reports)
 ---------------------------------------------------------
 Includes:
  - Disk Scanner v1 (simple directory scan)
  - Disk Scanner v2 (enhanced DFIR-style)
  - Memory IOC Scanner (process & parent/child)
  - HTML Report Generator

 All actions are READ-ONLY: no file deletion or modification.

 REQUIREMENTS:
  - Windows 10/11
  - PowerShell 5+
  - ioc_list.txt in the SAME folder as this script

 USAGE:
  - Open PowerShell in this folder
  - Run:  .\ForensicsIOC_Toolkit_Full.ps1
  - Use the menu to choose scans
#>

Clear-Host
Write-Host "==== FORENSICS IOC TOOLKIT (Full Edition) ====" -ForegroundColor Cyan

# ---------------------------------------------------------
# Helper: Load IOCs from ioc_list.txt
# ---------------------------------------------------------
function Get-IOCs {
    param(
        [string]$Path = "ioc_list.txt"
    )

    if (-not (Test-Path $Path)) {
        Write-Host "ERROR: $Path not found in current directory!" -ForegroundColor Red
        return $null
    }

    $iocs = Get-Content $Path | Where-Object { $_ -notmatch "^#|^\s*$" }
    Write-Host "Loaded $($iocs.Count) IOC items from $Path" -ForegroundColor Yellow
    return $iocs
}

# ---------------------------------------------------------
# Helper: Generate HTML report from PSCustomObject array
# ---------------------------------------------------------
function Write-HTMLReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Data,

        [string]$Title = "Forensics IOC Report",
        [string]$Output = "ioc_report.html"
    )

    if (-not $Data -or $Data.Count -eq 0) {
        Write-Host "No data to generate HTML report." -ForegroundColor Yellow
        return
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>$Title</title>
  <style>
    body { font-family: Segoe UI, sans-serif; margin: 20px; }
    h1 { color: #0A84FF; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    th { background: #0A84FF; color: white; }
    tr:nth-child(even) { background: #f2f2f2; }
    .alert { color: red; font-weight: bold; }
    .meta { color: #555; font-size: 0.9em; }
  </style>
</head>
<body>
  <h1>$Title</h1>
  <p class="meta">Generated: $(Get-Date)</p>
  <table>
    <tr>
"@

    # Table headers
    $columns = $Data[0].PSObject.Properties.Name
    foreach ($col in $columns) {
        $html += "      <th>$col</th>`n"
    }
    $html += "    </tr>`n"

    # Table rows
    foreach ($row in $Data) {
        $html += "    <tr>`n"
        foreach ($col in $columns) {
            $val = $row.$col
            if ($null -eq $val) { $val = "" }
            $valEscaped = [System.Web.HttpUtility]::HtmlEncode($val.ToString())
            if ($valEscaped -match "IOC|Suspicious|Malicious") {
                $html += "      <td class='alert'>$valEscaped</td>`n"
            }
            else {
                $html += "      <td>$valEscaped</td>`n"
            }
        }
        $html += "    </tr>`n"
    }

    $html += @"
  </table>
</body>
</html>
"@

    $html | Out-File $Output -Encoding UTF8
    Write-Host "HTML report generated: $Output" -ForegroundColor Green
}

# ---------------------------------------------------------
# Disk IOC Scanner v1 (simple directory scan)
# ---------------------------------------------------------
function Invoke-IOCScannerV1 {
    Write-Host "`n[+] Disk IOC Scanner v1 (simple)" -ForegroundColor Cyan

    $IOCs = Get-IOCs
    if ($null -eq $IOCs) { return }

    $ScanPath = Read-Host "Enter directory to scan (e.g., C:\Users\YourName\Downloads)"
    if (-not (Test-Path $ScanPath)) {
        Write-Host "ERROR: Directory does not exist!" -ForegroundColor Red
        return
    }

    Write-Host "Scanning: $ScanPath ..." -ForegroundColor Yellow
    $Results = @()

    Get-ChildItem -Recurse -File -Path $ScanPath -ErrorAction SilentlyContinue | ForEach-Object {
        $File = $_
        $Hash = $null

        try {
            $Hash = (Get-FileHash -Algorithm SHA256 -Path $File.FullName -ErrorAction Stop).Hash
        }
        catch {
            $Hash = $null
        }

        if ($IOCs -contains $File.Name) {
            $Results += [pscustomobject]@{
                Type = "Filename IOC"
                File = $File.FullName
                Hash = $Hash
            }
        }

        if ($IOCs -contains $File.FullName) {
            $Results += [pscustomobject]@{
                Type = "Path IOC"
                File = $File.FullName
                Hash = $Hash
            }
        }

        if ($Hash -and ($IOCs -contains $Hash)) {
            $Results += [pscustomobject]@{
                Type = "Hash IOC"
                File = $File.FullName
                Hash = $Hash
            }
        }
    }

    if ($Results.Count -gt 0) {
        Write-Host "`n=== IOC HITS FOUND (Disk v1) ===" -ForegroundColor Red
        $Results | Format-Table -AutoSize

        $csvPath = "ioc_hits_v1.csv"
        $htmlPath = "ioc_hits_v1.html"

        $Results | Export-Csv $csvPath -NoTypeInformation
        Write-HTMLReport -Data $Results -Title "Disk IOC Scan v1" -Output $htmlPath

        Write-Host "CSV saved:  $csvPath"
        Write-Host "HTML saved: $htmlPath"
    }
    else {
        Write-Host "`nNo IOC matches found in Disk v1 scan." -ForegroundColor Green
    }
}

# ---------------------------------------------------------
# Disk IOC Scanner v2 (enhanced DFIR)
# ---------------------------------------------------------
function Invoke-IOCScannerV2 {
    Write-Host "`n[+] Disk IOC Scanner v2 (enhanced)" -ForegroundColor Cyan

    $IOCs = Get-IOCs
    if ($null -eq $IOCs) { return }

    Write-Host "`nChoose Scan Mode:"
    Write-Host "  1. Scan specific directory"
    Write-Host "  2. Full system scan (C:\) - slower"
    $choice = Read-Host "Enter option (1 or 2)"

    switch ($choice) {
        "1" {
            $ScanPath = Read-Host "Enter directory path"
            if (-not (Test-Path $ScanPath)) {
                Write-Host "Invalid directory!" -ForegroundColor Red
                return
            }
        }
        "2" {
            $ScanPath = "C:\"
        }
        default {
            Write-Host "Invalid option" -ForegroundColor Red
            return
        }
    }

    Write-Host "`nStarting enhanced scan on: $ScanPath" -ForegroundColor Cyan

    $Results = @()
    $SuspiciousExt = @(".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".cmd")

    Get-ChildItem -Recurse -File -Path $ScanPath -ErrorAction SilentlyContinue | ForEach-Object {
        $File = $_
        $Hash = $null

        try {
            $Hash = (Get-FileHash -Algorithm SHA256 -Path $File.FullName -ErrorAction Stop).Hash
        }
        catch {
            $Hash = $null
        }

        if ($IOCs -contains $File.Name) {
            $Results += [pscustomobject]@{
                Type = "Filename IOC"
                File = $File.FullName
                Hash = $Hash
                Time = $File.LastWriteTime
            }
        }

        if ($IOCs -contains $File.FullName) {
            $Results += [pscustomobject]@{
                Type = "Path IOC"
                File = $File.FullName
                Hash = $Hash
                Time = $File.LastWriteTime
            }
        }

        if ($Hash -and ($IOCs -contains $Hash)) {
            $Results += [pscustomobject]@{
                Type = "Hash IOC"
                File = $File.FullName
                Hash = $Hash
                Time = $File.LastWriteTime
            }
        }

        # Suspicious recent files (last 2 days)
        if ($SuspiciousExt -contains $File.Extension) {
            if ($File.LastWriteTime -gt (Get-Date).AddDays(-2)) {
                $Results += [pscustomobject]@{
                    Type = "Suspicious Recent"
                    File = $File.FullName
                    Hash = $Hash
                    Time = $File.LastWriteTime
                }
            }
        }
    }

    if ($Results.Count -gt 0) {
        Write-Host "`n===== IOC HITS FOUND (Disk v2) =====" -ForegroundColor Red
        $Results | Format-Table -AutoSize

        $csvPath  = "ioc_hits_v2.csv"
        $jsonPath = "ioc_hits_v2.json"
        $htmlPath = "ioc_hits_v2.html"

        $Results | Export-Csv $csvPath -NoTypeInformation
        $Results | ConvertTo-Json | Out-File $jsonPath
        Write-HTMLReport -Data $Results -Title "Disk IOC Scan v2" -Output $htmlPath

        Write-Host "CSV saved:  $csvPath"
        Write-Host "JSON saved: $jsonPath"
        Write-Host "HTML saved: $htmlPath"
    }
    else {
        Write-Host "`nNo IOC matches detected in Disk v2 scan." -ForegroundColor Green
    }
}

# ---------------------------------------------------------
# Memory IOC Scanner (process & parent/child)
# ---------------------------------------------------------
function Invoke-MemoryIOCScanner {
    Write-Host "`n[+] Memory IOC Scanner" -ForegroundColor Cyan

    $IOCs = Get-IOCs
    if ($null -eq $IOCs) { return }

    $SuspiciousChildren = @(
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe",
        "python.exe", "nc.exe", "netcat.exe"
    )

    $SuspiciousParents = @(
        "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE",
        "chrome.exe", "msedge.exe", "iexplore.exe", "acrord32.exe"
    )

    Write-Host "Enumerating processes..." -ForegroundColor Yellow

    $procRaw = Get-CimInstance Win32_Process
    $procById = @{}
    foreach ($p in $procRaw) {
        $procById[$p.ProcessId] = $p
    }

    $Results = @()

    foreach ($p in $procRaw) {
        $procName  = $p.Name
        $procId    = $p.ProcessId
        $parentPid = $p.ParentProcessId
        $exePath   = $p.ExecutablePath
        $startTime = $null

        if ($p.CreationDate) {
            $startTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($p.CreationDate)
        }

        $parentName = $null
        if ($procById.ContainsKey($parentPid)) {
            $parentName = $procById[$parentPid].Name
        }

        $hash = $null
        if ($exePath -and (Test-Path $exePath)) {
            try {
                $hash = (Get-FileHash -Algorithm SHA256 -Path $exePath -ErrorAction Stop).Hash
            }
            catch {
                $hash = $null
            }
        }

        # Process name IOC
        if ($IOCs -contains $procName) {
            $Results += [pscustomobject]@{
                Category    = "Process Name IOC"
                ProcessName = $procName
                PID         = $procId
                ParentName  = $parentName
                ParentPID   = $parentPid
                Path        = $exePath
                Hash        = $hash
                StartTime   = $startTime
            }
        }

        # Process path IOC
        if ($exePath -and ($IOCs -contains $exePath)) {
            $Results += [pscustomobject]@{
                Category    = "Process Path IOC"
                ProcessName = $procName
                PID         = $procId
                ParentName  = $parentName
                ParentPID   = $parentPid
                Path        = $exePath
                Hash        = $hash
                StartTime   = $startTime
            }
        }

        # Process hash IOC
        if ($hash -and ($IOCs -contains $hash)) {
            $Results += [pscustomobject]@{
                Category    = "Process Hash IOC"
                ProcessName = $procName
                PID         = $procId
                ParentName  = $parentName
                ParentPID   = $parentPid
                Path        = $exePath
                Hash        = $hash
                StartTime   = $startTime
            }
        }

        # Suspicious parent-child
        if ($parentName) {
            $parentUpper = $parentName.ToUpper()
            $childLower  = $procName.ToLower()

            if ( ($SuspiciousChildren -contains $childLower) -and ($SuspiciousParents -contains $parentUpper) ) {
                $Results += [pscustomobject]@{
                    Category    = "Suspicious Parent-Child"
                    ProcessName = $procName
                    PID         = $procId
                    ParentName  = $parentName
                    ParentPID   = $parentPid
                    Path        = $exePath
                    Hash        = $hash
                    StartTime   = $startTime
                }
            }
        }
    }

    if ($Results.Count -gt 0) {
        Write-Host "`n===== MEMORY / PROCESS IOC HITS =====" -ForegroundColor Red
        $Results | Sort-Object Category, ProcessName | Format-Table -AutoSize

        $csvPath  = "memory_ioc_hits.csv"
        $jsonPath = "memory_ioc_hits.json"
        $htmlPath = "memory_ioc_hits.html"

        $Results | Export-Csv $csvPath -NoTypeInformation
        $Results | ConvertTo-Json | Out-File $jsonPath
        Write-HTMLReport -Data $Results -Title "Memory IOC Scan" -Output $htmlPath

        Write-Host "CSV saved:  $csvPath"
        Write-Host "JSON saved: $jsonPath"
        Write-Host "HTML saved: $htmlPath"
    }
    else {
        Write-Host "`nNo suspicious processes or memory IOCs detected." -ForegroundColor Green
    }
}

# ---------------------------------------------------------
# Main Menu
# ---------------------------------------------------------
function Show-MainMenu {
    while ($true) {
        Write-Host "`n============== MAIN MENU ==============" -ForegroundColor Cyan
        Write-Host "1. Disk IOC Scanner v1 (simple)"
        Write-Host "2. Disk IOC Scanner v2 (enhanced DFIR)"
        Write-Host "3. Memory IOC Scanner"
        Write-Host "4. Exit"
        $choice = Read-Host "Select an option"

        switch ($choice) {
            "1" { Invoke-IOCScannerV1 }
            "2" { Invoke-IOCScannerV2 }
            "3" { Invoke-MemoryIOCScanner }
            "4" { Write-Host "Exiting toolkit." -ForegroundColor Yellow; break }
            default { Write-Host "Invalid choice, try again." -ForegroundColor Red }
        }
    }
}

# Start the menu
Show-MainMenu
