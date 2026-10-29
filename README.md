# EventSage Local v2.4

Analyze Windows event exports and WinDbg text on your own PC. Log content is sent from your browser to a Python service on that same PC, not to pwnhacker.com or an AI service.

## Download

**[Download EventSage Local v2.4 for Windows](https://github.com/jaytrentwv/EventSage-Local/raw/refs/heads/main/downloads/EventSage-Local-v2.4.zip)**

Extract the ZIP, then double-click **Start-EventSage.bat**. Python 3.10+ is required; first run downloads dependencies. No administrator access is required.

## Windows setup

1. Install Python 3.10 or newer from https://www.python.org/downloads/windows/ if needed. Python 3.11 or 3.12 is a suitable choice. Enable the launcher or add Python to PATH.
2. Extract the complete ZIP into a writable folder, for example Documents\EventSage-Local. Do not launch from inside the ZIP.
3. Double-click **Start-EventSage.bat**. Administrator access is not required for the analyzer.
4. First run creates a `.venv` and downloads dependencies; internet access is required for setup. Subsequent runs work offline once installed.
5. Your browser opens **http://127.0.0.1:8766/**. Keep the command window open while using the app.
6. Choose an EVTX, XML, JSON, or CSV log (up to 150 MB), or upload WinDbg text through its separate control (up to 2 MB).
7. Press Ctrl+C in the command window to stop the service. Close the browser tab afterward.

## What it does

- Parses Windows event exports and groups known event patterns into incident cards.
- Shows restart/bugcheck evidence and nearby warning/error events.
- Reads WinDbg !analyze -v text; does not parse raw crash dumps.
- Offers browser-session acknowledgment and raw-event search.
- Uses rule-based correlation, not an external AI model.

## Privacy and limits

- Binds only to 127.0.0.1; rejects non-loopback addresses and unrecognized Host headers.
- No password is needed for local use. Do not configure a tunnel, reverse proxy, port forwarding, or LAN exposure for this package.
- Analysis is request-local and not intentionally saved as case history. EVTX processing uses a temporary file, removed after parsing; an abnormal termination may leave a temporary file for OS cleanup.
- Browser/OS memory, swap, and temporary-file behavior still apply. This is not a secure-erasure tool.
- The Back to Apps link opens pwnhacker.com; it does not transmit uploaded logs. The analyzer itself uses no external web assets or analytics.
- An unclean shutdown is a symptom, not proof of the cause. Findings support investigation; they do not establish driver culpability.
- Large logs can take time and substantial memory. Try a smaller time range if necessary.
- If port 8766 is occupied, stop the other process or the previous EventSage instance, then retry.

## Validation

Python and rendered JavaScript syntax, local-access enforcement, cross-origin rejection, sample JSON, UTF-16 XML, and WinDbg text were tested in a Linux development environment. The Windows BAT launcher and real EVTX processing still need testing on Windows.

## Distribution

This package contains application source and a launcher, not a bundled Python executable. It contains no hosting credentials, API keys, customer logs, or crash dumps. No software license has been assigned; the owner can choose one before public distribution.
