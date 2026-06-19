<#
.SYNOPSIS
    Collects volatile triage data from a live Windows host into timestamped JSON.

.DESCRIPTION
    Read-only first-response collection: processes, network connections, autoruns,
    scheduled tasks, services, local users/admins, logged-on users, recent files,
    and recent security/PowerShell events. Output is a single JSON file for later
    analysis (e.g. feeding timeline-builder.py).

    This does NOT modify the host beyond writing the output file. Run as
    Administrator for complete results.

.EXAMPLE
    .\triage-collector.ps1 -OutDir C:\evidence
#>
[CmdletBinding()]
param(
    [string]$OutDir = ".",
    [int]$EventHours = 24
)

$ErrorActionPreference = "SilentlyContinue"
$host_name = $env:COMPUTERNAME
$stamp     = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$outFile   = Join-Path $OutDir "triage-$host_name-$stamp.json"
$since     = (Get-Date).AddHours(-$EventHours)

Write-Host "[*] Collecting volatile triage data from $host_name ..." -ForegroundColor Cyan

$data = [ordered]@{
    meta = [ordered]@{
        hostname    = $host_name
        collected   = (Get-Date).ToUniversalTime().ToString("o")
        collector   = $env:USERNAME
        os           = (Get-CimInstance Win32_OperatingSystem).Caption
        event_window_hours = $EventHours
    }

    processes = Get-CimInstance Win32_Process | ForEach-Object {
        [ordered]@{
            pid          = $_.ProcessId
            ppid         = $_.ParentProcessId
            name         = $_.Name
            path         = $_.ExecutablePath
            command_line = $_.CommandLine
            created      = $_.CreationDate
        }
    }

    network = Get-NetTCPConnection -State Established, Listen | ForEach-Object {
        [ordered]@{
            local  = "$($_.LocalAddress):$($_.LocalPort)"
            remote = "$($_.RemoteAddress):$($_.RemotePort)"
            state  = $_.State.ToString()
            pid    = $_.OwningProcess
        }
    }

    autoruns_run_keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    ) | ForEach-Object {
        $key = $_
        $props = Get-ItemProperty -Path $key
        if ($props) {
            $props.PSObject.Properties |
                Where-Object { $_.Name -notlike "PS*" } |
                ForEach-Object { [ordered]@{ hive = $key; name = $_.Name; value = $_.Value } }
        }
    }

    scheduled_tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } |
        ForEach-Object {
            [ordered]@{
                name    = $_.TaskName
                path    = $_.TaskPath
                actions = ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments })
            }
        }

    services_running = Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" } |
        ForEach-Object { [ordered]@{ name = $_.Name; display = $_.DisplayName; path = $_.PathName; start = $_.StartMode } }

    local_admins = (Get-LocalGroupMember -Group "Administrators" |
        ForEach-Object { $_.Name })

    logged_on = (query user 2>$null)

    recent_security_events = Get-WinEvent -FilterHashtable @{
            LogName = "Security"; Id = 4624, 4625, 4672, 4688, 4720, 4732, 4698, 7045; StartTime = $since
        } -MaxEvents 500 | ForEach-Object {
            [ordered]@{ time = $_.TimeCreated.ToUniversalTime().ToString("o"); id = $_.Id; msg = ($_.Message -split "`n")[0] }
        }

    recent_powershell = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-PowerShell/Operational"; Id = 4104; StartTime = $since
        } -MaxEvents 200 | ForEach-Object {
            [ordered]@{ time = $_.TimeCreated.ToUniversalTime().ToString("o"); id = $_.Id; msg = ($_.Message -split "`n")[0] }
        }
}

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$data | ConvertTo-Json -Depth 6 | Out-File -FilePath $outFile -Encoding utf8

Write-Host "[+] Triage written to $outFile" -ForegroundColor Green
Write-Host "    Processes: $($data.processes.Count)  Connections: $($data.network.Count)  Tasks: $($data.scheduled_tasks.Count)" -ForegroundColor Green
