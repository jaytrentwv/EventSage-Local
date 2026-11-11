# Remote Access Examiner v0.1 - Windows PowerShell 5.1+, read-only
# Run: powershell.exe -NoProfile -File .\RemoteAccessExaminer.ps1 -Days 7
[CmdletBinding()]
param(
    [ValidateRange(1,90)][int]$Days = 7,
    [string]$OutputRoot = (Join-Path $env:USERPROFILE 'Documents\RemoteAccessExaminer'),
    [ValidateRange(100,20000)][int]$MaxEventsPerLog = 3000
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$started = Get-Date
$since = $started.AddDays(-$Days)
$stamp = $started.ToString('yyyyMMdd_HHmmss')
$outDir = Join-Path $OutputRoot ("{0}_{1}" -f $env:COMPUTERNAME,$stamp)
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$events = New-Object 'System.Collections.Generic.List[object]'
$inventory = New-Object 'System.Collections.Generic.List[object]'
$warnings = New-Object 'System.Collections.Generic.List[string]'

function Add-Item {
    param([string]$Category,[string]$Finding,[string]$Detail,[string]$Severity='Info')
    $inventory.Add([pscustomobject]@{ Category=$Category; Finding=$Finding; Detail=$Detail; Severity=$Severity })
}
function Get-EventFields {
    param($Event)
    $map=@{}
    try {
        [xml]$xml=$Event.ToXml()
        foreach($node in @($xml.Event.EventData.Data)) {
            $name=[string]$node.Name
            if($name) { $map[$name]=[string]$node.'#text' }
        }
        $i=0
        foreach($node in @($xml.Event.UserData.ChildNodes)) {
            foreach($child in @($node.ChildNodes)) {
                if($child.LocalName) {$map[[string]$child.LocalName]=[string]$child.InnerText}
            }
        }
    } catch {}
    return $map
}
function Add-Event {
    param($Event,[string]$Source,[string]$Kind,[string]$Meaning,[string]$Level='Review')
    $data=Get-EventFields $Event
    $user=(@($data['TargetDomainName'],$data['TargetUserName']) | Where-Object {$_}) -join '\'
    if(-not $user) {$user=$data['User']}
    $remote=@($data['IpAddress'],$data['ClientAddress'],$data['SourceNetworkAddress'],$data['Address']) |
        Where-Object { $_ -and $_ -notin @('-','::1','127.0.0.1') } | Select-Object -First 1
    $events.Add([pscustomobject]@{
        Time=$Event.TimeCreated.ToString('o'); Source=$Source; EventId=$Event.Id
        Kind=$Kind; Interpretation=$Meaning; User=$user
        RemoteAddress=($remote -join ''); LogonType=$data['LogonType']
        Workstation=$data['WorkstationName']; RecordId=$Event.RecordId
        Level=$Level
    })
}
function Read-Log {
    param([string]$Name,[int[]]$Ids,[scriptblock]$Handler)
    try {
        $query=@{LogName=$Name; Id=$Ids; StartTime=$since}
        $rows=@(Get-WinEvent -FilterHashtable $query -MaxEvents $MaxEventsPerLog -ErrorAction Stop)
        if($rows.Count -ge $MaxEventsPerLog) {
            $warnings.Add("Log $Name reached the $MaxEventsPerLog event cap; older events in the selected period may be excluded.")
        }
        foreach($e in $rows) { & $Handler $e }
    } catch {
        $warnings.Add("Could not fully query $Name : $($_.Exception.Message)")
    }
}
Write-Host "Remote Access Examiner v0.1 - local, read-only" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME | Since: $since"
$admin=$false
try {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    $admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
if(-not $admin){ $warnings.Add('Not elevated: Security log and other artifacts may be inaccessible. Run as Administrator for a more complete report.') }

# RDP configuration is not proof of a session.
try {
    $ts=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
    Add-Item 'RDP configuration' 'RDP host setting' $(if($ts.fDenyTSConnections -eq 0){'Remote Desktop host connections allowed'}else{'Remote Desktop host connections disabled'}) 'Info'
} catch { $warnings.Add("RDP configuration unavailable: $($_.Exception.Message)") }
try {
    $listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {$_.LocalPort -in @(3389,5900,5985,5986)})
    foreach($l in $listeners){ Add-Item 'Network listener' ("TCP "+$l.LocalPort) ("Local="+$l.LocalAddress+" PID="+$l.OwningProcess) 'Review' }
} catch { $warnings.Add("TCP listener inventory unavailable: $($_.Exception.Message)") }

# Do not call 1149 a full logon: it is authentication activity.
Read-Log 'Security' @(4624,4625,4778,4779) {
    param($e)
    $d=Get-EventFields $e
    switch($e.Id) {
        4624 { if($d['LogonType'] -eq '10') { Add-Event $e 'Security' 'RDP logon' 'Successful RemoteInteractive logon (type 10)' 'High' } }
        4625 { if($d['LogonType'] -in @('10','3')) {
            Add-Event $e 'Security' 'Failed logon' 'Failed network or RemoteInteractive logon; may not be RDP' 'Review'
        } }
        4778 { Add-Event $e 'Security' 'Session reconnect' 'Windows session reconnected; investigate session type' 'Review' }
        4779 { Add-Event $e 'Security' 'Session disconnect' 'Windows session disconnected; investigate session type' 'Review' }
    }
}
Read-Log 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' @(1149) {
    param($e)
    Add-Event $e 'RDP RemoteConnectionManager' 'RDP authentication' 'Authentication succeeded; not proof of desktop session' 'Review'
}
Read-Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' @(21,22,23,24,25) {
    param($e)
    switch($e.Id) {
        21 { Add-Event $e 'RDP LocalSessionManager' 'Session logon' 'Session logon succeeded; correlate with Security 4624' 'High' }
        22 { Add-Event $e 'RDP LocalSessionManager' 'Shell start' 'Shell start notification; correlate with session' 'Review' }
        23 { Add-Event $e 'RDP LocalSessionManager' 'Session logoff' 'Session logoff succeeded' 'Info' }
        24 { Add-Event $e 'RDP LocalSessionManager' 'Session disconnect' 'Session disconnected' 'Info' }
        25 { Add-Event $e 'RDP LocalSessionManager' 'Session reconnect' 'Session reconnected' 'Review' }
    }
}

$remoteTools=@(
    @{Name='ScreenConnect / ConnectWise Control'; Rx='screenconnect|connectwise.control|connectwisecontrol'},
    @{Name='AnyDesk'; Rx='anydesk'},
    @{Name='Atera / Splashtop'; Rx='atera|splashtop|srservice'},
    @{Name='RustDesk'; Rx='rustdesk'},
    @{Name='TeamViewer'; Rx='teamviewer'},
    @{Name='BeyondTrust / Bomgar'; Rx='bomgar|beyondtrust'},
    @{Name='Zoho Assist'; Rx='zohoassist|zohomeeting'},
    @{Name='LogMeIn / GoTo'; Rx='logmein|gotoassist|gotomypc'},
    @{Name='Remote Utilities'; Rx='rutserv|remote.utilities'},
    @{Name='DWService'; Rx='dwagent|dwservice'},
    @{Name='MeshCentral'; Rx='meshagent|meshcentral'},
    @{Name='Chrome Remote Desktop'; Rx='chromoting|remoting_host|chrome.remote.desktop'},
    @{Name='Radmin'; Rx='radmin'},
    @{Name='VNC'; Rx='tightvnc|ultravnc|realvnc|vncserver|winvnc'}
)
function Find-Tool([string]$Text) {
    foreach($tool in $remoteTools) { if($Text -match $tool.Rx){ return $tool.Name } }
    return $null
}
# Inventory only: installed/active software does not prove unauthorized access.
try {
    foreach($key in @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )){
        foreach($app in @(Get-ItemProperty $key -ErrorAction SilentlyContinue)){
            if(-not $app.DisplayName){continue}
            $found=Find-Tool ([string]$app.DisplayName)
            if($found){ Add-Item 'Installed software' $found ("Name="+$app.DisplayName+" Version="+$app.DisplayVersion+" Publisher="+$app.Publisher) 'Review' }
        }
    }
} catch { $warnings.Add("Installed app inventory incomplete: $($_.Exception.Message)") }
try {
    foreach($svc in @(Get-CimInstance Win32_Service -ErrorAction Stop)){
        $found=Find-Tool ($svc.Name+' '+$svc.DisplayName+' '+$svc.PathName)
        if($found){ Add-Item 'Service' $found ("Service="+$svc.Name+" State="+$svc.State+" StartMode="+$svc.StartMode+" Path="+$svc.PathName) 'Review' }
    }
} catch { $warnings.Add("Service inventory incomplete: $($_.Exception.Message)") }
try {
    foreach($proc in @(Get-CimInstance Win32_Process -ErrorAction Stop)){
        $found=Find-Tool ($proc.Name+' '+$proc.ExecutablePath+' '+$proc.CommandLine)
        if($found){ Add-Item 'Running process' $found ("PID="+$proc.ProcessId+" Path="+$proc.ExecutablePath) 'Review' }
    }
} catch { $warnings.Add("Process inventory incomplete: $($_.Exception.Message)") }
try {
    foreach($task in @(Get-ScheduledTask -ErrorAction Stop)){
        $action=(@($task.Actions | ForEach-Object {$_.Execute+' '+$_.Arguments}) -join ' ')
        $found=Find-Tool ($task.TaskName+' '+$task.TaskPath+' '+$action)
        if($found){ Add-Item 'Scheduled task' $found ("Task="+$task.TaskPath+$task.TaskName+" State="+$task.State+" Action="+$action) 'Review' }
    }
} catch { $warnings.Add("Task inventory incomplete: $($_.Exception.Message)") }

# Optional Sysmon events: presence depends on local configuration.
Read-Log 'Microsoft-Windows-Sysmon/Operational' @(1) {
    param($e)
    $d=Get-EventFields $e
    $found=Find-Tool ($d['Image']+' '+$d['CommandLine']+' '+$d['ParentImage'])
    if($found){ Add-Event $e 'Sysmon' 'Remote tool execution' ("Process creation matching "+$found+"; verify authorization") 'Review' }
}

$eventData=@($events | Sort-Object Time)
$inventoryData=@($inventory | Sort-Object Category,Finding)
$summary=[ordered]@{
    Tool='Remote Access Examiner'; Version='0.1'; Computer=$env:COMPUTERNAME
    GeneratedAt=$started.ToString('o'); Since=$since.ToString('o'); Elevated=$admin
    EventCount=$eventData.Count; InventoryCount=$inventoryData.Count
    EventCapPerLog=$MaxEventsPerLog; Warnings=@($warnings)
    Disclaimer='Artifacts indicate activity or configuration, not proof of compromise. Absence of findings is not proof of absence.'
}
$report=[ordered]@{ Summary=$summary; Events=$eventData; Inventory=$inventoryData }
$report | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $outDir 'report.json') -Encoding UTF8
$eventData | Export-Csv (Join-Path $outDir 'events.csv') -NoTypeInformation -Encoding UTF8
$inventoryData | Export-Csv (Join-Path $outDir 'inventory.csv') -NoTypeInformation -Encoding UTF8
function Html([object]$s){ return [System.Net.WebUtility]::HtmlEncode([string]$s) }
function TableHtml([object[]]$rows,[string[]]$cols) {
    if(-not $rows -or $rows.Count -eq 0){return '<p>No entries found in this category.</p>'}
    $sb=New-Object System.Text.StringBuilder
    [void]$sb.Append('<table><thead><tr>')
    foreach($c in $cols){[void]$sb.Append('<th>'+(Html $c)+'</th>')}
    [void]$sb.Append('</tr></thead><tbody>')
    foreach($r in $rows){
        [void]$sb.Append('<tr>')
        foreach($c in $cols){[void]$sb.Append('<td>'+(Html $r.$c)+'</td>')}
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}
$style='body{font:14px Segoe UI,Arial,sans-serif;max-width:1200px;margin:32px auto;padding:0 20px;color:#dbe6f2;background:#101820}h1,h2{color:#62d5f5}table{border-collapse:collapse;width:100%;margin:15px 0 28px;font-size:12px}td,th{border:1px solid #3d5364;padding:7px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#233746}tr:nth-child(even){background:#172631}.note{background:#213343;padding:12px;border-left:4px solid #ffc36b}small{color:#adc3d1}'
$warningItems=(@($warnings | ForEach-Object { '<li>'+(Html $_)+'</li>' }) -join '')
$htmlReport='<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Remote Access Examiner</title><style>'+$style+'</style></head><body>'+
'<h1>Remote Access Examiner v0.1</h1><p><b>Computer:</b> '+(Html $env:COMPUTERNAME)+' | <b>From:</b> '+(Html $since)+' | <b>Generated:</b> '+(Html $started)+'</p>'+
'<p class="note">This report is investigative evidence, not a malware verdict. Legitimate remote administration can produce these records. Missing or cleared logs limit conclusions. Contains usernames, IP addresses and software paths: keep private.</p>'+
'<h2>Collection warnings</h2><ul>'+$warningItems+'</ul>'+
'<h2>Remote access session indicators ('+$eventData.Count+')</h2>'+(TableHtml $eventData @('Time','Source','EventId','Kind','User','RemoteAddress','LogonType','Interpretation'))+
'<h2>Installed and active remote access inventory ('+$inventoryData.Count+')</h2>'+(TableHtml $inventoryData @('Category','Finding','Detail','Severity'))+
'<small>Read-only collection. No remote access configuration or security agent settings were modified.</small></body></html>'
[System.IO.File]::WriteAllText((Join-Path $outDir 'index.html'),$htmlReport,[System.Text.Encoding]::UTF8)
Write-Host ("Report: {0}" -f (Join-Path $outDir 'index.html')) -ForegroundColor Green
Write-Host ("Events: {0}; Inventory findings: {1}; Warnings: {2}" -f $eventData.Count,$inventoryData.Count,$warnings.Count)
