using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics.Eventing.Reader;
using System.Net.Http;
using System.Net.Mail;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Linq;

namespace DisconnectedHousekeeping
{
    internal class Program
    {
        private static readonly string Hostname = Environment.MachineName;
        private static volatile bool _stopRequested;

        public static void Main(string[] args)
        {
            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                _stopRequested = true;
            };

            // Help
            if (args != null && args.Any(a =>
                    a.Equals("/?", StringComparison.OrdinalIgnoreCase) ||
                    a.Equals("-?", StringComparison.OrdinalIgnoreCase)))
            {
                PrintUsage();
                return;
            }

            bool isTestMode = args != null && args.Any(a =>
                a.Equals("/test", StringComparison.OrdinalIgnoreCase));

            if (!IsAdministrator())
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Warning: Application is not running elevated. Some operations may fail (EventLog access requires Admin).");
                Console.ResetColor();
            }

            if (isTestMode)
            {
                Console.WriteLine("----------------------------------------------------------------");
                Console.WriteLine($"DisconnectedHousekeeping TEST MODE on {Hostname}");
                Console.WriteLine("No logoff actions or notifications will be performed.");
                Console.WriteLine("----------------------------------------------------------------");
                try
                {
                    RunTestMode();
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Critical Error in TEST MODE: {ex}");
                    Console.ResetColor();
                }
                Console.WriteLine("TEST MODE finished.");
                return;
            }

            var settings = HousekeepingSettings.Load();

            bool continuous = args != null && args.Any(a =>
                a.Equals("/c", StringComparison.OrdinalIgnoreCase) ||
                a.Equals("-c", StringComparison.OrdinalIgnoreCase) ||
                a.Equals("--continuous", StringComparison.OrdinalIgnoreCase));

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine($"DisconnectedHousekeeping started on {Hostname}");
            Console.WriteLine($"Threshold: {settings.ThresholdMinutes} min");
            Console.WriteLine($"Fallback EventLog: {settings.UseEventLogFallback}");
            Console.WriteLine($"Fallback IdleTime: {settings.UseIdleTimeFallback}");
            Console.WriteLine("----------------------------------------------------------------");

            if (!continuous)
            {
                Console.WriteLine("Mode: Single-run");
                try
                {
                    ProcessOnce(settings);
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Critical Error: {ex}");
                    Console.ResetColor();
                }
                Console.WriteLine("Done. (Single run finished)");
                return;
            }

            Console.WriteLine($"Mode: Continuous (Interval: {settings.ScanIntervalSeconds}s)");

            while (!_stopRequested)
            {
                try
                {
                    ProcessOnce(settings);
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Loop Error: {ex}");
                    Console.ResetColor();
                }

                var waited = 0;
                while (waited < settings.ScanIntervalSeconds && !_stopRequested)
                {
                    Thread.Sleep(1000);
                    waited++;
                }
            }

            Console.WriteLine("DisconnectedHousekeeping stopping.");
        }

        private static void PrintUsage()
        {
            Console.WriteLine("DisconnectedHousekeeping");
            Console.WriteLine("Usage: DisconnectedHousekeeping.exe [/c] [/test] [/?]");
            Console.WriteLine();
            Console.WriteLine("  /c       Run continuously (loop). Default is single-run and exit.");
            Console.WriteLine("  /test    Run in diagnostics mode (no logoffs, just dump WTS + EventLog info).");
            Console.WriteLine("  /?       Show this help.");
        }

        private static void ProcessOnce(HousekeepingSettings settings)
        {
            var nowUtc = DateTime.UtcNow;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Scanning sessions...");

            var sessions = WtsHelper.EnumerateSessions();
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Found {sessions.Count} total sessions.");

            foreach (var s in sessions)
            {
                // Only consider disconnected sessions
                if (s.State != WtsHelper.WTS_CONNECTSTATE_CLASS.WTSDisconnected)
                    continue;

                if (string.IsNullOrWhiteSpace(s.User))
                {
                    Console.WriteLine($"[INFO] Skipping Session {s.SessionId} (No Username/System session?)");
                    continue;
                }

                Console.WriteLine($"--- Processing Disconnected Session {s.SessionId} ({s.Domain}\\{s.User}) ---");

                // Determine disconnect duration
                DateTime? disconnectUtc = s.DisconnectTimeUtc;
                string disconnectSource = "WTS-API";

                // Step 1: Check Native API
                if (disconnectUtc == null)
                {
                    Console.WriteLine($"[DEBUG] WTS API returned NULL for DisconnectTime. Attempting fallbacks...");
                    bool resolved = false;

                    // Step 2: Event Log Fallback
                    if (settings.UseEventLogFallback)
                    {
                        Console.WriteLine($"[DEBUG] Attempting EventLog Fallback (looking for EventID 40)...");
                        if (RdsEventLogHelper.TryGetDisconnectTimeUtc(s.SessionId, out var evtUtc, out var recordId))
                        {
                            disconnectUtc = evtUtc;
                            disconnectSource = $"EventLog(ID:{recordId})";
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[SUCCESS] Found disconnect time via EventLog: {evtUtc:O}");
                            Console.ResetColor();
                            resolved = true;
                        }
                        else
                        {
                            Console.WriteLine($"[DEBUG] EventLog Fallback failed (no matching Event 40 found or log cleared).");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[DEBUG] EventLog Fallback is DISABLED in config.");
                    }

                    // Step 3: Idle Time Fallback
                    if (!resolved && settings.UseIdleTimeFallback)
                    {
                        Console.WriteLine($"[DEBUG] Attempting IdleTime Fallback...");
                        int idleSec = WtsHelper.QueryIdleSeconds(s.SessionId);

                        Console.WriteLine($"[DEBUG] Raw Idle Seconds from API: {idleSec}");

                        if (idleSec >= 0)
                        {
                            var approx = nowUtc - TimeSpan.FromSeconds(idleSec);
                            disconnectUtc = approx;
                            disconnectSource = "IdleTimeCalc";
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[SUCCESS] Calculated disconnect time via IdleTime: {approx:O}");
                            Console.ResetColor();
                            resolved = true;
                        }
                        else
                        {
                            Console.WriteLine($"[DEBUG] IdleTime Fallback failed (returned {idleSec}).");
                        }
                    }
                    else if (!resolved && !settings.UseIdleTimeFallback)
                    {
                        Console.WriteLine($"[DEBUG] IdleTime Fallback is DISABLED in config.");
                    }

                    // Final Check
                    if (!resolved)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[SKIP] Could not determine disconnect time for Session {s.SessionId}. Skipping.");
                        Console.WriteLine($"       Debug Info: InfoLevel={s.InfoLevel}, Flags={s.SessionFlags}, Logon={s.LogonTimeUtc:O}, LastInput={s.LastInputTimeUtc:O}");
                        Console.ResetColor();
                        continue;
                    }
                }
                else
                {
                    Console.WriteLine($"[DEBUG] Native WTS API provided time: {disconnectUtc:O}");
                }

                // Calculate Duration
                var duration = nowUtc - disconnectUtc.Value;
                Console.WriteLine($"[ANALYSIS] Disconnected for {(int)duration.TotalMinutes} min (Source: {disconnectSource}) | Threshold: {settings.ThresholdMinutes} min");

                if (duration.TotalMinutes >= settings.ThresholdMinutes)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[ACTION] Threshold exceeded. Logging off Session {s.SessionId}...");
                    Console.ResetColor();

                    // Forcefully log off this session and wait
                    var result = ForceLogoffAndWait(s.SessionId);

                    var outcome = result ? "Success" : $"Failed (Win32Error={Marshal.GetLastWin32Error()})";
                    Console.WriteLine($"[RESULT] Logoff Session {s.SessionId}: {outcome}");

                    // Notify
                    var details = new LogoffDetails
                    {
                        Hostname = Hostname,
                        Username = s.User,
                        Domain = s.Domain,
                        SessionId = s.SessionId,
                        DisconnectedDuration = duration,
                        DisconnectTimeUtc = disconnectUtc.Value,
                        Result = outcome
                    };
                    Notify(settings, details);
                }
                else
                {
                    Console.WriteLine($"[INFO] Session {s.SessionId} is under threshold. No action taken.");
                }
            }
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Scan complete.");
        }

        /// <summary>
        /// Test-/Diagnosemodus: dump WTS-Infos und Eventlog-Vergleich, keine Logoffs.
        /// </summary>
        private static void RunTestMode()
        {
            var nowUtc = DateTime.UtcNow;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] TEST: Enumerating sessions...");

            var sessions = WtsHelper.EnumerateSessions();
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] TEST: Found {sessions.Count} total sessions on {Hostname}.");

            foreach (var s in sessions.OrderBy(x => x.SessionId))
            {
                Console.WriteLine("------------------------------------------------------------");
                Console.WriteLine($"Session {s.SessionId}: {s.Domain}\\{s.User}");
                Console.WriteLine($"  State: {s.State}, InfoLevel={s.InfoLevel}, Flags={s.SessionFlags}");
                Console.WriteLine($"  LogonTimeUtc:      {s.LogonTimeUtc:O}");
                Console.WriteLine($"  ConnectTimeUtc:    {s.ConnectTimeUtc:O}");
                Console.WriteLine($"  DisconnectTimeUtc: {s.DisconnectTimeUtc:O}");
                Console.WriteLine($"  LastInputTimeUtc:  {s.LastInputTimeUtc:O}");

                if (s.State == WtsHelper.WTS_CONNECTSTATE_CLASS.WTSDisconnected)
                {
                    Console.WriteLine("  TEST: Session is DISCONNECTED. Checking EventLog (ID 40) for comparison...");

                    if (RdsEventLogHelper.TryGetDisconnectTimeUtc(s.SessionId, out var evtUtc, out var recId))
                    {
                        Console.WriteLine($"  EventLog: RecordId={recId}, TimeUtc={evtUtc:O}");

                        if (s.DisconnectTimeUtc.HasValue)
                        {
                            var delta = s.DisconnectTimeUtc.Value - evtUtc;
                            Console.WriteLine($"  Δ(WTS - EventLog): {delta.TotalSeconds:F1} seconds");
                        }
                        else
                        {
                            Console.WriteLine("  WTS DisconnectTimeUtc is NULL, EventLog has a value.");
                        }

                        var durEvt = nowUtc - evtUtc;
                        Console.WriteLine($"  Approx. disconnected duration (EventLog): {durEvt.TotalMinutes:F1} min");
                    }
                    else
                    {
                        Console.WriteLine("  EventLog: No matching EventID 40 found for this SessionID in the last N records.");
                    }

                    if (s.DisconnectTimeUtc.HasValue)
                    {
                        var durWts = nowUtc - s.DisconnectTimeUtc.Value;
                        Console.WriteLine($"  Approx. disconnected duration (WTS):      {durWts.TotalMinutes:F1} min");
                    }
                }
            }

            Console.WriteLine("------------------------------------------------------------");
            Console.WriteLine("TEST MODE completed. Review the output above to validate WTS vs EventLog behaviour.");
        }

        private static bool ForceLogoffAndWait(int sessionId)
        {
            try
            {
                // bWait = true ensures the function returns when session is logged off
                var ok = WtsHelper.WTSLogoffSession(IntPtr.Zero, sessionId, true);
                return ok;
            }
            catch
            {
                return false;
            }
        }

        private static void Notify(HousekeepingSettings settings, LogoffDetails details)
        {
            if (settings.EmailEnabled)
            {
                try
                {
                    Console.WriteLine("[NOTIFY] Sending Email...");
                    SendEmail(settings, details);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] Email notification failed: {ex.Message}");
                }
            }

            if (settings.RestEnabled)
            {
                try
                {
                    Console.WriteLine("[NOTIFY] Sending REST Request...");
                    SendRest(settings, details).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] REST notification failed: {ex.Message}");
                }
            }
        }

        private static void SendEmail(HousekeepingSettings s, LogoffDetails d)
        {
            var subjectTemplate = string.IsNullOrWhiteSpace(s.EmailSubject)
                ? "Disconnected session logged off on {{host}}: {{account}} (Session {{session}})"
                : s.EmailSubject;

            var subject = RenderTemplate(subjectTemplate, d);

            var body = new StringBuilder();
            body.AppendLine($"Hostname: {d.Hostname}");
            body.AppendLine($"User: {d.Domain}\\{d.Username}");
            body.AppendLine($"SessionId: {d.SessionId}");
            body.AppendLine($"Disconnected Since (UTC): {d.DisconnectTimeUtc:O}");
            body.AppendLine($"Disconnected Duration: {FormatDuration(d.DisconnectedDuration)}");
            body.AppendLine($"Logoff Result: {d.Result}");

            using (var msg = new MailMessage())
            {
                msg.From = new MailAddress(s.EmailFrom);
                foreach (var to in s.EmailTo.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    msg.To.Add(to.Trim());
                }
                msg.Subject = subject;
                msg.Body = body.ToString();

                using (var client = new SmtpClient(s.SmtpHost, s.SmtpPort))
                {
                    client.EnableSsl = s.SmtpEnableSsl;
                    if (!string.IsNullOrWhiteSpace(s.SmtpUser))
                    {
                        client.Credentials = new System.Net.NetworkCredential(s.SmtpUser, s.SmtpPassword);
                    }
                    client.Send(msg);
                }
            }
        }

        private static string RenderTemplate(string template, LogoffDetails d)
        {
            var now = DateTime.Now;
            var account = string.IsNullOrWhiteSpace(d.Domain) ? (d.Username ?? string.Empty) : ($"{d.Domain}\\{d.Username}");

            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["name"] = d.Username ?? string.Empty,
                ["user"] = d.Username ?? string.Empty,
                ["domain"] = d.Domain ?? string.Empty,
                ["account"] = account,
                ["host"] = string.IsNullOrWhiteSpace(d.Hostname) ? Hostname : d.Hostname,
                ["hostname"] = string.IsNullOrWhiteSpace(d.Hostname) ? Hostname : d.Hostname,
                ["session"] = d.SessionId.ToString(),
                ["disconnect_utc"] = d.DisconnectTimeUtc.ToUniversalTime().ToString("O"),
                ["disconnect_local"] = d.DisconnectTimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                ["duration"] = FormatDuration(d.DisconnectedDuration),
                ["minutes"] = Math.Round(d.DisconnectedDuration.TotalMinutes, 0).ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["result"] = d.Result ?? string.Empty,
                ["datetime"] = now.ToString("yyyy-MM-dd HH:mm:ss"),
                ["date"] = now.ToString("yyyy-MM-dd"),
                ["time"] = now.ToString("HH:mm:ss")
            };

            string Replacer(Match m)
            {
                var key = m.Groups[1].Value;
                return map.TryGetValue(key, out var val) ? val : m.Value; // leave unknown tokens unchanged
            }

            return Regex.Replace(template ?? string.Empty, @"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", Replacer);
        }

        private static async System.Threading.Tasks.Task SendRest(HousekeepingSettings s, LogoffDetails d)
        {
            using (var client = new HttpClient { Timeout = TimeSpan.FromSeconds(s.RestTimeoutSeconds) })
            {
                if (!string.IsNullOrWhiteSpace(s.RestAuthHeaderName))
                {
                    client.DefaultRequestHeaders.Add(s.RestAuthHeaderName, s.RestAuthHeaderValue ?? string.Empty);
                }

                var json = BuildJson(d);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var resp = await client.PostAsync(s.RestUrl, content).ConfigureAwait(false);
                resp.EnsureSuccessStatusCode();
            }
        }

        private static string BuildJson(LogoffDetails d)
        {
            string Esc(string s) => string.IsNullOrEmpty(s) ? string.Empty : s
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n");

            var sb = new StringBuilder();
            sb.Append('{');
            sb.Append("\"hostname\":\"").Append(Esc(d.Hostname)).Append("\",");
            sb.Append("\"username\":\"").Append(Esc(d.Username)).Append("\",");
            sb.Append("\"domain\":\"").Append(Esc(d.Domain)).Append("\",");
            sb.Append("\"sessionId\":").Append(d.SessionId).Append(',');
            sb.Append("\"disconnectTimeUtc\":\"").Append(d.DisconnectTimeUtc.ToUniversalTime().ToString("O")).Append("\",");
            sb.Append("\"disconnectedDurationMinutes\":").Append(Math.Round(d.DisconnectedDuration.TotalMinutes, 2).ToString(System.Globalization.CultureInfo.InvariantCulture)).Append(',');
            sb.Append("\"logoffResult\":\"").Append(Esc(d.Result)).Append("\"");
            sb.Append('}');
            return sb.ToString();
        }

        private static string FormatDuration(TimeSpan ts)
        {
            return string.Format("{0}d {1}h {2}m {3}s", ts.Days, ts.Hours, ts.Minutes, ts.Seconds);
        }

        private static bool IsAdministrator()
        {
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }
    }

    internal class LogoffDetails
    {
        public string Hostname { get; set; }
        public string Username { get; set; }
        public string Domain { get; set; }
        public int SessionId { get; set; }
        public DateTime DisconnectTimeUtc { get; set; }
        public TimeSpan DisconnectedDuration { get; set; }
        public string Result { get; set; }
    }

    internal class HousekeepingSettings
    {
        public double ThresholdMinutes { get; set; }
        public int ScanIntervalSeconds { get; set; }
        public bool UseEventLogFallback { get; set; }
        public bool UseIdleTimeFallback { get; set; }

        public bool EmailEnabled { get; set; }
        public string SmtpHost { get; set; }
        public int SmtpPort { get; set; }
        public bool SmtpEnableSsl { get; set; }
        public string EmailFrom { get; set; }
        public string EmailTo { get; set; }
        public string SmtpUser { get; set; }
        public string SmtpPassword { get; set; }
        public string EmailSubject { get; set; }

        public bool RestEnabled { get; set; }
        public string RestUrl { get; set; }
        public string RestAuthHeaderName { get; set; }
        public string RestAuthHeaderValue { get; set; }
        public int RestTimeoutSeconds { get; set; }

        public static HousekeepingSettings Load()
        {
            double ParseDouble(string key, double def)
            {
                var v = ConfigurationManager.AppSettings[key];
                return double.TryParse(v, out var d) ? d : def;
            }

            int ParseInt(string key, int def)
            {
                var v = ConfigurationManager.AppSettings[key];
                return int.TryParse(v, out var d) ? d : def;
            }

            bool ParseBool(string key, bool def)
            {
                var v = ConfigurationManager.AppSettings[key];
                return v == null ? def : v.Equals("true", StringComparison.OrdinalIgnoreCase) || v.Equals("1");
            }

            string Get(string key, string def = null)
            {
                return ConfigurationManager.AppSettings[key] ?? def;
            }

            return new HousekeepingSettings
            {
                ThresholdMinutes = ParseDouble("ThresholdMinutes", 60),
                ScanIntervalSeconds = ParseInt("ScanIntervalSeconds", 60),
                UseEventLogFallback = ParseBool("UseEventLogFallback", true),
                UseIdleTimeFallback = ParseBool("UseIdleTimeFallback", false),

                EmailEnabled = ParseBool("EmailEnabled", false),
                SmtpHost = Get("SmtpHost", ""),
                SmtpPort = ParseInt("SmtpPort", 25),
                SmtpEnableSsl = ParseBool("SmtpEnableSsl", false),
                EmailFrom = Get("EmailFrom", ""),
                EmailTo = Get("EmailTo", ""),
                SmtpUser = Get("SmtpUser", ""),
                SmtpPassword = Get("SmtpPassword", ""),
                EmailSubject = Get("EmailSubject", ""),

                RestEnabled = ParseBool("RestEnabled", false),
                RestUrl = Get("RestUrl", ""),
                RestAuthHeaderName = Get("RestAuthHeaderName", null),
                RestAuthHeaderValue = Get("RestAuthHeaderValue", null),
                RestTimeoutSeconds = ParseInt("RestTimeoutSeconds", 15)
            };
        }
    }

    internal static class WtsHelper
    {
        [DllImport("Wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            out IntPtr ppSessionInfo,
            out int pCount);

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("Wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WTSQuerySessionInformation(
            IntPtr hServer,
            int sessionId,
            WTS_INFO_CLASS wtsInfoClass,
            out IntPtr ppBuffer,
            out int pBytesReturned);

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSLogoffSession(IntPtr hServer, int sessionId, bool bWait);

        public static List<WtsSession> EnumerateSessions()
        {
            var result = new List<WtsSession>();
            IntPtr pSessions = IntPtr.Zero;
            int count = 0;
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out pSessions, out count))
            {
                var err = Marshal.GetLastWin32Error();
                Console.WriteLine($"[ERROR] WTSEnumerateSessions failed with Win32 Error: {err}");
                return result;
            }

            try
            {
                int dataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                for (int i = 0; i < count; i++)
                {
                    var p = new IntPtr(pSessions.ToInt64() + i * dataSize);
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure(p, typeof(WTS_SESSION_INFO));

                    var session = new WtsSession
                    {
                        SessionId = si.SessionID,
                        State = si.State
                    };

                    session.User = QueryString(si.SessionID, WTS_INFO_CLASS.WTSUserName);
                    session.Domain = QueryString(si.SessionID, WTS_INFO_CLASS.WTSDomainName);

                    FillTimes(si.SessionID, session);
                    result.Add(session);
                }
            }
            finally
            {
                if (pSessions != IntPtr.Zero) WTSFreeMemory(pSessions);
            }
            return result;
        }

        private static void FillTimes(int sessionId, WtsSession session)
        {
            IntPtr buffer;
            int bytes;
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WTS_INFO_CLASS.WTSSessionInfoEx, out buffer, out bytes))
            {
                return;
            }
            try
            {
                var info = (WTSINFOEX)Marshal.PtrToStructure(buffer, typeof(WTSINFOEX));
                session.InfoLevel = (int)info.Level;
                if (info.Level == 1)
                {
                    var l1 = info.Data.WTSInfoExLevel1;
                    session.SessionFlags = l1.SessionFlags;

                    session.LogonTimeUtc = ToDateTime(l1.LogonTime);
                    session.ConnectTimeUtc = ToDateTime(l1.ConnectTime);
                    session.DisconnectTimeUtc = ToDateTime(l1.DisconnectTime);
                    session.LastInputTimeUtc = ToDateTime(l1.LastInputTime);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
            }
        }

        private static DateTime? ToDateTime(long fileTime)
        {
            if (fileTime <= 0) return null;
            try { return DateTime.FromFileTimeUtc(fileTime); } catch { return null; }
        }

        private static string QueryString(int sessionId, WTS_INFO_CLASS info)
        {
            IntPtr buffer;
            int bytes;
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, info, out buffer, out bytes) || buffer == IntPtr.Zero)
                return string.Empty;
            try
            {
                var s = Marshal.PtrToStringUni(buffer);
                return s ?? string.Empty;
            }
            finally
            {
                WTSFreeMemory(buffer);
            }
        }

        public static int QueryIdleSeconds(int sessionId)
        {
            IntPtr buffer;
            int bytes;
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WTS_INFO_CLASS.WTSIdleTime, out buffer, out bytes) || buffer == IntPtr.Zero)
                return -1;
            try
            {
                if (bytes >= 4)
                {
                    return Marshal.ReadInt32(buffer);
                }
                return -1;
            }
            finally
            {
                WTSFreeMemory(buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public int SessionID;
            public IntPtr pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }

        public class WtsSession
        {
            public int SessionId { get; set; }
            public string User { get; set; }
            public string Domain { get; set; }
            public WTS_CONNECTSTATE_CLASS State { get; set; }
            public DateTime? ConnectTimeUtc { get; set; }
            public DateTime? DisconnectTimeUtc { get; set; }
            public DateTime? LastInputTimeUtc { get; set; }
            public DateTime? LogonTimeUtc { get; set; }
            public int InfoLevel { get; set; }
            public int SessionFlags { get; set; }
        }

        public enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        private enum WTS_INFO_CLASS
        {
            WTSUserName = 5,
            WTSDomainName = 7,
            WTSIdleTime = 17,
            WTSSessionInfoEx = 25
        }

        // WTSINFOEX layout (correct for WTSINFOEX_LEVEL1_W)
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WTSINFOEX
        {
            public uint Level;
            public WTSINFOEX_LEVEL Data;
        }

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
        private struct WTSINFOEX_LEVEL
        {
            [FieldOffset(0)]
            public WTSINFOEX_LEVEL1_W WTSInfoExLevel1;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WTSINFOEX_LEVEL1_W
        {
            public uint SessionId;
            public WTS_CONNECTSTATE_CLASS SessionState;
            public int SessionFlags;

            // WINSTATIONNAME_LENGTH = 32 (+1)
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)]
            public string WinStationName;

            // USERNAME_LENGTH = 20 (+1)
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)]
            public string UserName;

            // DOMAIN_LENGTH = 17 (+1)
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)]
            public string DomainName;

            // LARGE_INTEGER times in FILETIME (100ns since 1601)
            public long LogonTime;
            public long ConnectTime;
            public long DisconnectTime;
            public long LastInputTime;
            public long CurrentTime;

            public uint IncomingBytes;
            public uint OutgoingBytes;
            public uint IncomingFrames;
            public uint OutgoingFrames;
            public uint IncomingCompressedBytes;
            public uint OutgoingCompressedBytes;
        }
    }

    internal static class RdsEventLogHelper
    {
        private const string Channel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

        public static bool TryGetDisconnectTimeUtc(int sessionId, out DateTime utc, out long recordId)
        {
            utc = default(DateTime);
            recordId = 0L;

            try
            {
                // HYBRID-Ansatz:
                // Filter nach EventID 40 (Session disconnected) und suche SessionID im XML.
                string xPath = "*[System[(EventID=40)]]";

                var query = new EventLogQuery(Channel, PathType.LogName, xPath)
                {
                    ReverseDirection = true // Neueste zuerst
                };

                using (var reader = new EventLogReader(query))
                {
                    int maxEventsToScan = 100;
                    int scanned = 0;

                    for (EventRecord rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                    {
                        if (scanned++ > maxEventsToScan) break;

                        using (rec)
                        {
                            string xml = rec.ToXml();
                            string searchPattern = $">{sessionId}<";

                            if (xml.Contains(searchPattern))
                            {
                                if (rec.TimeCreated.HasValue)
                                {
                                    utc = rec.TimeCreated.Value.ToUniversalTime();
                                    recordId = rec.RecordId.GetValueOrDefault(0L);

                                    Console.ForegroundColor = ConsoleColor.Green;
                                    Console.WriteLine($"[DEBUG] Found Session {sessionId} in EventRecord {recordId} (Time: {utc:HH:mm:ss})");
                                    Console.ResetColor();
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] EventLog logic error: {ex.Message}");
            }
            return false;
        }
    }
}
