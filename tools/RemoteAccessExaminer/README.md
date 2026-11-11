# Remote Access Examiner v0.1 (prototype)

A standalone, **read-only** Windows remote-access forensic collector, developed as a separate prototype under the EventSage-Local repository. **It does not depend on EventSage.** Intended future home: its own dedicated repository or a TrentForge module.

## Supported environment

- Windows 10/11; Windows PowerShell 5.1 (included with Windows)
- No Python, downloads, third-party modules, or internet connectivity required
- Run locally on a computer you own or are authorized to examine
- Administrator PowerShell recommended; non-elevated operation may have incomplete logs
- Collector writes its own output directory under Documents; it does not modify the examined system's configuration, quarantine, logs, services, tasks, ACLs, or firewall rules

## Run

In PowerShell, from the directory containing the script:

```powershell
powershell.exe -NoProfile -File .\RemoteAccessExaminer.ps1 -Days 7
```

For a 30-day window:

```powershell
powershell.exe -NoProfile -File .\RemoteAccessExaminer.ps1 -Days 30 -MaxEventsPerLog 10000
```

Reports are written to:

`%USERPROFILE%\Documents\RemoteAccessExaminer\COMPUTERNAME_YYYYMMDD_HHMMSS\`

Open `index.html` in a browser; `events.csv`, `inventory.csv`, and `report.json` are also created. **Reports may contain private usernames, IP addresses, and executable paths. Do not publish them to GitHub or public forums.**

## Current evidence sources

- Security: 4624 (logon type 10), 4625 (failed logon types 10/3), 4778, 4779
- RemoteConnectionManager/Operational: 1149 (RDP authentication activity)
- LocalSessionManager/Operational: 21–25 (session logon/shell/logoff/disconnect/reconnect)
- RDP hosting configuration and common listener ports
- Installed application inventory, Windows services, running processes, scheduled tasks
- Sysmon process-creation Event 1 if Sysmon is installed
- Search terms for AnyDesk, ScreenConnect / ConnectWise, Atera, Splashtop, RustDesk, TeamViewer, BeyondTrust, Zoho Assist, LogMeIn/GoTo, Remote Utilities, DWService, MeshCentral, Chrome Remote Desktop, Radmin, VNC

## Interpreting the report

- **RDP client usage** (`mstsc.exe`) is different from **incoming RDP host logons**.
- Event 1149 is evidence of successful authentication activity, not necessarily a completed interactive desktop session.
- Event 4624 logon type 10 is stronger evidence of RemoteInteractive logon; correlate timestamps and users.
- An installed or running remote-support application is not proof of unauthorized access.
- Absence of records is **not** evidence that remote access never happened: logging may have been disabled, events rolled over, agents can maintain their own logs, and not every remote-support tool uses Windows RDP.
- Log scanning is bounded by `MaxEventsPerLog` and adds warnings when limits are reached.
- Local clock adjustments, log retention, lack of admin rights, and tampering can affect conclusions.
- The v0.1 collector is a **prototype** and has not been validated against all target Windows releases or vendor versions.

## Roadmap

- v0.2: correlate sessions and timestamps; detect service creation and scheduled-task installation history; parse RDP client outbound evidence; gather per-vendor connection logs when present; richer HTML filtering
- v0.3: portable, signed release; offline event-log imports, hashed evidence manifest, and baseline comparisons
- No cloud upload; no stealth collection; no security-agent disabling or quarantine manipulation
