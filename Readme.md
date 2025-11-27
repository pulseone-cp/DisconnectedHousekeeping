# DisconnectedHousekeeping

A small Windows console utility that scans Remote Desktop Services (RDS) sessions and logs off users whose sessions have been in "Disconnected" state longer than a configurable threshold. Optional notifications can be sent via SMTP email and/or a REST webhook.

This project targets .NET Framework 4.8 and is intended to run on Windows (workstations or servers). It can run once (single pass) or continuously at a fixed interval.

## Features

- Detects disconnected RDS sessions and logs them off after `ThresholdMinutes`
- Single-run or continuous mode
- Multiple strategies to determine disconnect time:
  - Primary: WTS `WTSINFOEX` data (fast, direct)
  - Fallback: Windows Event Log (TerminalServices LocalSessionManager, EventID 40)
  - Fallback: Idle time (last input) when enabled
- Optional notifications
  - SMTP email
  - REST webhook with customizable auth header

## Usage

Place the built `DisconnectedHousekeeping.exe` alongside its `DisconnectedHousekeeping.exe.config` (generated from `App.config`). Then run:

```
DisconnectedHousekeeping.exe [/c] [/?]
```

Flags:

- `/c`, `-c`, `--continuous` — run continuously, scanning every `ScanIntervalSeconds`
- `/?`, `-?` — print brief usage

Notes:

- Running elevated (as Administrator) is recommended. Accessing the Event Log fallback typically requires administrative rights. The app will warn if it is not elevated.
- To run persistently, consider scheduling via Windows Task Scheduler or wrapping with a service runner. The project itself does not install a Windows Service.

## Configuration (App.config)

All configuration is read from `appSettings` in `App.config`/`DisconnectedHousekeeping.exe.config`.

Thresholds and scheduling:

- `ThresholdMinutes` (double, default `60`) — log off if disconnected longer than this many minutes
- `ScanIntervalSeconds` (int, default `60`) — loop interval when running in continuous mode

Disconnect time strategies:

- `UseEventLogFallback` (bool, default `true`) — when WTS data lacks a disconnect timestamp (e.g., some Windows Server versions), read it from Event Log channel `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`, `EventID=40`
- `UseIdleTimeFallback` (bool, default `false`) — use session idle time (last input) as a heuristic if neither primary nor Event Log source is available

SMTP email notifications:

- `EmailEnabled` (bool, default `false`)
- `SmtpHost` (string)
- `SmtpPort` (int, default `25`)
- `SmtpEnableSsl` (bool, default `false`)
- `EmailFrom` (string)
- `EmailTo` (comma/semicolon-separated list)
- `SmtpUser` (string, optional)
- `SmtpPassword` (string, optional)
- `EmailSubject` (string, optional) — supports placeholders like `{{name}}`, `{{host}}`, `{{datetime}}` (see list below)

Subject template placeholders (for `EmailSubject`):

- `{{name}}` / `{{user}}` — the username
- `{{domain}}` — the user domain (may be empty)
- `{{account}}` — combined account name (`DOMAIN\\User` or just `User` when domain is empty)
- `{{host}}` / `{{hostname}}` — the machine name where the utility runs
- `{{session}}` — numeric Session ID
- `{{disconnect_utc}}` — disconnect timestamp in UTC (ISO 8601, `O` format)
- `{{disconnect_local}}` — disconnect timestamp in local time (`yyyy-MM-dd HH:mm:ss`)
- `{{duration}}` — human-readable disconnected duration (e.g., `0d 2h 15m 3s`)
- `{{minutes}}` — disconnected duration in whole minutes
- `{{result}}` — logoff result string
- `{{datetime}}` — current local date/time when the email is produced (`yyyy-MM-dd HH:mm:ss`)
- `{{date}}` — current local date (`yyyy-MM-dd`)
- `{{time}}` — current local time (`HH:mm:ss`)

Notes:

- Placeholders are case-insensitive and any unknown placeholders are left unchanged.
- If `EmailSubject` is empty, the default subject is: `Disconnected session logged off on {{host}}: {{domain}}\\{{name}} (Session {{session}})`

REST notifications:

- `RestEnabled` (bool, default `false`)
- `RestUrl` (string) — endpoint to POST JSON payload
- `RestAuthHeaderName` (string, optional) — e.g., `Authorization`
- `RestAuthHeaderValue` (string, optional) — e.g., `Bearer <token>`
- `RestTimeoutSeconds` (int, default `15`)

Example `App.config` snippet:

```xml
<appSettings>
  <!-- Housekeeping thresholds -->
  <add key="ThresholdMinutes" value="60"/>
  <add key="ScanIntervalSeconds" value="60"/>
  <!-- Fallbacks when WTSSessionInfoEx.DisconnectTime is missing (e.g., on Windows Server 2022) -->
  <add key="UseEventLogFallback" value="true"/>
  <add key="UseIdleTimeFallback" value="false"/>

  <!-- Email notification settings -->
  <add key="EmailEnabled" value="false"/>
  <add key="SmtpHost" value=""/>
  <add key="SmtpPort" value="25"/>
  <add key="SmtpEnableSsl" value="false"/>
  <add key="EmailFrom" value=""/>
  <add key="EmailTo" value=""/>
  <add key="SmtpUser" value=""/>
  <add key="SmtpPassword" value=""/>
  <add key="EmailSubject" value="Disconnected {{account}} (Session {{session}}) on {{host}} at {{datetime}}"/>

  <!-- REST notification settings -->
  <add key="RestEnabled" value="false"/>
  <add key="RestUrl" value=""/>
  <add key="RestAuthHeaderName" value=""/>
  <add key="RestAuthHeaderValue" value=""/>
  <add key="RestTimeoutSeconds" value="15"/>
</appSettings>
```

## How it works (high level)

- Enumerates sessions via `Wtsapi32` (`WTSEnumerateSessions`) and queries details using `WTSQuerySessionInformation`.
- Determines disconnect time using the following order:
  1) WTS `WTSINFOEX` (if available for the OS)
  2) Event Log fallback by scanning the Operational log for `EventID=40` entries matching the `SessionId`
  3) Idle time fallback (when enabled) as a heuristic
- If a session has been disconnected longer than `ThresholdMinutes`, the tool calls `WTSLogoffSession`.
- When configured, it sends notifications:
  - Email: basic SMTP with optional credentials and SSL
  - REST: HTTP POST with a small JSON payload (hostname, user, session, disconnect time, duration, result)

## Build

Requirements:

- Windows (for running and for P/Invoke headers to make sense)
- .NET Framework 4.8 Developer Pack
- JetBrains Rider or Visual Studio 2019/2022

Steps:

1. Open `DisconnectedHousekeeping.sln`
2. Restore/build using your IDE
3. Output binaries are in `DisconnectedHousekeeping\bin\Debug` or `DisconnectedHousekeeping\bin\Release`

## Deployment

- Copy `DisconnectedHousekeeping.exe` and `DisconnectedHousekeeping.exe.config` to the target machine
- Update values in the `.config` file to match your environment
- Run elevated for best results, especially if `UseEventLogFallback` is `true`

## Troubleshooting

- No sessions are being logged off:
  - Ensure you are running as Administrator (Event Log access may fail otherwise)
  - Verify that sessions are actually in Disconnected state long enough to exceed `ThresholdMinutes`
  - If on newer Windows Server and disconnect time appears missing, keep `UseEventLogFallback=true`
  - If Event Log rotation removed older events, consider lowering the threshold or raising log size

- Email notification fails:
  - Check `SmtpHost`, `SmtpPort`, and `SmtpEnableSsl`
  - If auth is required, set `SmtpUser` and `SmtpPassword`
  - Verify firewall or relay permissions

- REST notification fails:
  - Confirm `RestUrl` and that it accepts POST with `application/json`
  - If auth is needed, set `RestAuthHeaderName`/`RestAuthHeaderValue`
  - Inspect HTTP status codes; non-2xx responses are treated as failures

## Security notes

- SMTP credentials are stored in plain text in the `.config`. Prefer a low-privilege account or use a mail relay.
- Use HTTPS endpoints for REST webhooks and avoid embedding long-lived secrets directly when possible.

## License

No license has been specified in this repository. Add a license if you intend to distribute this software.
