package dev.wirelessadb.autostart;

import android.content.Context;
import android.content.SharedPreferences;
import android.provider.Settings;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringReader;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Monitors active wireless ADB TCP/TLS client connections and manages per-IP aliases and socket kicks.
 *
 * <p>Primary path: {@code WirelessAdbHook} running in {@code system_server} reads
 * {@code /proc/net/tcp} and {@code /proc/net/tcp6} natively (SELinux {@code proc_net_tcp_udp})
 * without requiring Root, and publishes snapshots to {@link Settings.Global#getString} under
 * {@link #GLOBAL_CLIENTS}.
 *
 * <p>Fallback & Control path: When Root is granted in SukiSU/KernelSU/Magisk, {@code StatusActivity}
 * can also read {@code /proc/net/tcp*} before a post-update reboot and forcibly close individual
 * client sockets via {@code /system/bin/ss -K}.
 */
public final class AdbClientMonitor {
    public static final String ACTION_REFRESH_CLIENTS = "dev.wirelessadb.autostart.REFRESH_CLIENTS";
    public static final String GLOBAL_CLIENTS = "wirelessadb_autostart_clients";
    private static final String HEADER_PREFIX = "#v1\t";
    private static final String PREFS_ALIASES = "client_aliases";
    private static final Pattern SAFE_IP = Pattern.compile("^[0-9a-fA-F:.]{2,45}$");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    public static final class ClientEntry {
        public final String remoteIp;
        public final int remotePort;
        public final int localPort;
        public final String transport;
        public final long connectedSinceMs;

        public ClientEntry(String remoteIp, int remotePort, int localPort,
                           String transport, long connectedSinceMs) {
            this.remoteIp = remoteIp;
            this.remotePort = remotePort;
            this.localPort = localPort;
            this.transport = transport == null || transport.isEmpty() ? "TCP" : transport;
            this.connectedSinceMs = connectedSinceMs;
        }

        public String key() {
            return remoteIp + ":" + remotePort + "@" + localPort;
        }

        public String remoteEndpoint() {
            if (remoteIp.indexOf(':') >= 0) {
                return "[" + remoteIp + "]:" + remotePort;
            }
            return remoteIp + ":" + remotePort;
        }
    }

    public static final class Snapshot {
        public final boolean fromHook;
        public final long updatedAtMs;
        public final List<ClientEntry> clients;

        public Snapshot(boolean fromHook, long updatedAtMs, List<ClientEntry> clients) {
            this.fromHook = fromHook;
            this.updatedAtMs = updatedAtMs;
            this.clients = clients;
        }
    }

    public static final class KickResult {
        public final boolean rootInvoked;
        public final boolean success;
        public final String detail;

        public KickResult(boolean rootInvoked, boolean success, String detail) {
            this.rootInvoked = rootInvoked;
            this.success = success;
            this.detail = detail == null ? "" : detail;
        }
    }

    private AdbClientMonitor() {}

    /** Scans /proc/net/tcp and /proc/net/tcp6 directly (callable from system_server). */
    public static List<ClientEntry> scanProcNet(int tcpPort, int tlsPort,
                                                Map<String, Long> sinceTracker, long nowMs) {
        Map<String, ClientEntry> found = new LinkedHashMap<>();
        scanFile("/proc/net/tcp", false, tcpPort, tlsPort, sinceTracker, nowMs, found);
        scanFile("/proc/net/tcp6", true, tcpPort, tlsPort, sinceTracker, nowMs, found);
        return sortClients(found.values());
    }

    /** Fallback scan via su when system_server hook has not been loaded yet. */
    public static List<ClientEntry> scanViaRootFallback(int tcpPort, int tlsPort) {
        long now = System.currentTimeMillis();
        Map<String, ClientEntry> found = new LinkedHashMap<>();
        RootCommandProvider.ExecResult tcp4 =
                RootCommandProvider.execRoot("cat /proc/net/tcp 2>/dev/null", 1_500L);
        if (!tcp4.invoked) return null;
        if (tcp4.isSuccess() && !tcp4.output.isEmpty()) {
            parseProcReader(new BufferedReader(new StringReader(tcp4.output)),
                    false, tcpPort, tlsPort, null, now, found);
        }
        RootCommandProvider.ExecResult tcp6 =
                RootCommandProvider.execRoot("cat /proc/net/tcp6 2>/dev/null", 1_500L);
        if (tcp6.isSuccess() && !tcp6.output.isEmpty()) {
            parseProcReader(new BufferedReader(new StringReader(tcp6.output)),
                    true, tcpPort, tlsPort, null, now, found);
        }
        return sortClients(found.values());
    }

    private static void scanFile(String path, boolean ipv6, int tcpPort, int tlsPort,
                                 Map<String, Long> sinceTracker, long nowMs,
                                 Map<String, ClientEntry> out) {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            parseProcReader(reader, ipv6, tcpPort, tlsPort, sinceTracker, nowMs, out);
        } catch (Throwable ignored) { }
    }

    private static void parseProcReader(BufferedReader reader, boolean ipv6,
                                        int tcpPort, int tlsPort,
                                        Map<String, Long> sinceTracker, long nowMs,
                                        Map<String, ClientEntry> out) {
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("sl")) continue;
                String[] parts = WHITESPACE.split(trimmed);
                if (parts.length < 4) continue;

                // State 01 == TCP_ESTABLISHED
                if (!"01".equalsIgnoreCase(parts[3])) continue;

                int localPort = parsePort(parts[1]);
                if (localPort <= 0) continue;
                boolean matchesTcp = tcpPort > 0 && localPort == tcpPort;
                boolean matchesTls = tlsPort > 0 && localPort == tlsPort;
                if (!matchesTcp && !matchesTls) continue;

                String remoteIp = parseIpAddress(parts[2], ipv6);
                int remotePort = parsePort(parts[2]);
                if (remoteIp == null || remotePort <= 0) continue;

                String transport = (matchesTls && !matchesTcp) ? "TLS" : "TCP";
                String key = remoteIp + ":" + remotePort + "@" + localPort;
                long since = nowMs;
                if (sinceTracker != null) {
                    Long existing = sinceTracker.get(key);
                    if (existing != null && existing > 0L) {
                        since = existing;
                    }
                }
                if (!out.containsKey(key)) {
                    out.put(key, new ClientEntry(remoteIp, remotePort, localPort, transport, since));
                }
            }
        } catch (Throwable ignored) { }
    }

    private static int parsePort(String addrPort) {
        int colon = addrPort.indexOf(':');
        if (colon < 0 || colon + 1 >= addrPort.length()) return -1;
        try {
            return Integer.parseInt(addrPort.substring(colon + 1), 16);
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }

    private static String parseIpAddress(String addrPort, boolean ipv6) {
        int colon = addrPort.indexOf(':');
        if (colon <= 0) return null;
        String hex = addrPort.substring(0, colon);
        try {
            byte[] bytes;
            if (!ipv6 && hex.length() == 8) {
                bytes = new byte[4];
                decodeLittleEndianWord(hex, 0, bytes, 0);
            } else if (ipv6 && hex.length() == 32) {
                bytes = new byte[16];
                for (int w = 0; w < 4; w++) {
                    decodeLittleEndianWord(hex, w * 8, bytes, w * 4);
                }
            } else {
                return null;
            }
            InetAddress address = InetAddress.getByAddress(bytes);
            String host = address.getHostAddress();
            if (host == null) return null;
            int pct = host.indexOf('%');
            return pct > 0 ? host.substring(0, pct) : host;
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** Linux procfs prints each 32-bit network word in host (little-endian) hex byte order. */
    private static void decodeLittleEndianWord(String hex, int charOffset, byte[] out, int byteOffset) {
        out[byteOffset] = (byte) Integer.parseInt(hex.substring(charOffset + 6, charOffset + 8), 16);
        out[byteOffset + 1] = (byte) Integer.parseInt(hex.substring(charOffset + 4, charOffset + 6), 16);
        out[byteOffset + 2] = (byte) Integer.parseInt(hex.substring(charOffset + 2, charOffset + 4), 16);
        out[byteOffset + 3] = (byte) Integer.parseInt(hex.substring(charOffset, charOffset + 2), 16);
    }

    private static List<ClientEntry> sortClients(java.util.Collection<ClientEntry> items) {
        List<ClientEntry> list = new ArrayList<>(items);
        Collections.sort(list, Comparator
                .comparing((ClientEntry c) -> c.remoteIp)
                .thenComparingInt(c -> c.remotePort));
        return list;
    }

    /** Publishes active client list from system_server into Settings.Global. */
    public static boolean writeGlobalSnapshot(Context systemContext, List<ClientEntry> clients, long nowMs) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(HEADER_PREFIX).append(nowMs);
            if (clients != null) {
                for (ClientEntry c : clients) {
                    sb.append('\n')
                            .append(c.remoteIp).append('|')
                            .append(c.remotePort).append('|')
                            .append(c.localPort).append('|')
                            .append(c.transport).append('|')
                            .append(c.connectedSinceMs);
                }
            }
            return Settings.Global.putString(
                    systemContext.getContentResolver(), GLOBAL_CLIENTS, sb.toString());
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Reads the latest client snapshot published by system_server. */
    public static Snapshot readGlobalSnapshot(Context context) {
        String raw = null;
        try {
            raw = Settings.Global.getString(context.getContentResolver(), GLOBAL_CLIENTS);
        } catch (Throwable ignored) { }
        if (raw == null || !raw.startsWith(HEADER_PREFIX)) {
            return new Snapshot(false, 0L, Collections.emptyList());
        }
        String[] lines = raw.split("\n");
        long updatedAt = 0L;
        try {
            updatedAt = Long.parseLong(lines[0].substring(HEADER_PREFIX.length()).trim());
        } catch (Throwable ignored) { }

        List<ClientEntry> list = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) continue;
            String[] cols = line.split("\\|");
            if (cols.length < 4) continue;
            try {
                String ip = cols[0].trim();
                int rPort = Integer.parseInt(cols[1].trim());
                int lPort = Integer.parseInt(cols[2].trim());
                String transport = cols[3].trim();
                long since = cols.length >= 5 ? Long.parseLong(cols[4].trim()) : 0L;
                if (!ip.isEmpty() && rPort > 0 && lPort > 0) {
                    list.add(new ClientEntry(ip, rPort, lPort, transport, since));
                }
            } catch (Throwable ignored) { }
        }
        return new Snapshot(true, updatedAt, list);
    }

    /** Forcibly closes a connected ADB client TCP socket via `ss -K` using Root. */
    public static KickResult disconnectClientAsRoot(String remoteIp, int remotePort,
                                                    int localPort, boolean allPortsForIp) {
        if (remoteIp == null || !SAFE_IP.matcher(remoteIp).matches()) {
            return new KickResult(false, false, "无效客户端 IP");
        }
        if (localPort < 1 || localPort > 65535) {
            return new KickResult(false, false, "无效本地端口");
        }
        if (!allPortsForIp && (remotePort < 1 || remotePort > 65535)) {
            return new KickResult(false, false, "无效远端端口");
        }

        String dstExpr = remoteIp.indexOf(':') >= 0
                ? RootCommandProvider.shellQuote("[" + remoteIp + "]")
                : RootCommandProvider.shellQuote(remoteIp);
        String filter = (!allPortsForIp && remotePort > 0)
                ? String.format(Locale.US, "sport = :%d and dport = :%d", localPort, remotePort)
                : String.format(Locale.US, "sport = :%d", localPort);

        String cmd = "/system/bin/ss -K dst " + dstExpr + " " + RootCommandProvider.shellQuote(filter)
                + " || ss -K dst " + dstExpr + " " + RootCommandProvider.shellQuote(filter);
        RootCommandProvider.ExecResult res = RootCommandProvider.execRoot(cmd, 3_000L);
        if (!res.invoked) {
            return new KickResult(false, false, "未获取到 Root 权限（请在 SukiSU / Root 管理器中授权本应用）");
        }
        if (res.exitCode != 0) {
            String msg = res.output.trim();
            if (msg.isEmpty()) msg = "ss -K 退出码 " + res.exitCode;
            return new KickResult(true, false, msg);
        }
        return new KickResult(true, true, res.output.trim());
    }

    public static String getAlias(Context context, String ip) {
        if (ip == null || ip.isEmpty()) return "";
        String saved = aliasPrefs(context).getString(ip, "");
        if (saved != null && !saved.trim().isEmpty()) return saved.trim();
        if ("127.0.0.1".equals(ip) || "::1".equals(ip)) return "本机回环";
        return "";
    }

    public static void setAlias(Context context, String ip, String alias) {
        if (ip == null || ip.isEmpty()) return;
        SharedPreferences.Editor editor = aliasPrefs(context).edit();
        String trimmed = alias == null ? "" : alias.trim();
        if (trimmed.isEmpty()) {
            editor.remove(ip);
        } else {
            editor.putString(ip, trimmed.length() > 32 ? trimmed.substring(0, 32) : trimmed);
        }
        editor.apply();
    }

    private static SharedPreferences aliasPrefs(Context context) {
        Context storage = context.isDeviceProtectedStorage()
                ? context
                : context.createDeviceProtectedStorageContext();
        return storage.getSharedPreferences(PREFS_ALIASES, Context.MODE_PRIVATE);
    }
}
