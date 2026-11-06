package dev.wirelessadb.autostart;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Process;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Executes the small, fixed set of root operations requested by system_server or StatusActivity. */
public final class RootCommandProvider extends ContentProvider {
    public static final String AUTHORITY = "dev.wirelessadb.autostart.root";
    public static final Uri URI = Uri.parse("content://" + AUTHORITY);
    public static final String METHOD_SET_PROPERTY = "set_property";
    public static final String EXTRA_VALUE = "value";
    private static final String PROP_TCP_PORT = "service.adb.tcp.port";
    private static final String PROP_RESTART = "ctl.restart";
    private static final String VALUE_ADBD = "adbd";
    private static final String[] ROOT_EXECUTABLES = {
            "/data/adb/ksu/bin/su",
            "/product/bin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "su"
    };

    static final class ExecResult {
        final boolean invoked;
        final int exitCode;
        final String output;

        ExecResult(boolean invoked, int exitCode, String output) {
            this.invoked = invoked;
            this.exitCode = exitCode;
            this.output = output == null ? "" : output;
        }

        boolean isSuccess() {
            return invoked && exitCode == 0;
        }
    }

    @Override public boolean onCreate() {
        return true;
    }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        if (Binder.getCallingUid() != Process.SYSTEM_UID) {
            throw new SecurityException("Only system_server may request root operations");
        }
        Bundle result = new Bundle();
        if (!METHOD_SET_PROPERTY.equals(method) || arg == null || extras == null) {
            return result;
        }

        String value = extras.getString(EXTRA_VALUE);
        if (!isAllowedProperty(arg, value)) return result;
        result.putBoolean("success", setPropertyAsRoot(arg, value));
        return result;
    }

    private static boolean isAllowedProperty(String key, String value) {
        if (PROP_RESTART.equals(key)) return VALUE_ADBD.equals(value);
        if (!PROP_TCP_PORT.equals(key) || value == null) return false;
        try {
            int port = Integer.parseInt(value);
            return port == -1 || (port >= 1 && port <= 65535);
        } catch (NumberFormatException ignored) {
            return false;
        }
    }

    private static boolean setPropertyAsRoot(String key, String value) {
        String command = "setprop " + shellQuote(key) + " " + shellQuote(value);
        return execRoot(command, 2_000L).isSuccess();
    }

    static ExecResult execRoot(String command, long timeoutMs) {
        ExecResult lastAttempt = new ExecResult(false, -1, "");
        for (String executable : ROOT_EXECUTABLES) {
            java.lang.Process process = null;
            try {
                process = new ProcessBuilder(executable, "-c", command)
                        .redirectErrorStream(true)
                        .start();
                try { process.getOutputStream().close(); } catch (Throwable ignored) { }

                final InputStream in = process.getInputStream();
                final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                Thread reader = new Thread(() -> {
                    byte[] chunk = new byte[4096];
                    int read;
                    try {
                        while ((read = in.read(chunk)) != -1) {
                            if (buffer.size() < 262_144) {
                                buffer.write(chunk, 0, read);
                            }
                        }
                    } catch (Throwable ignored) { }
                }, "wadb-su-reader");
                reader.setDaemon(true);
                reader.start();

                if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
                    process.destroyForcibly();
                    continue;
                }
                reader.join(300L);
                int code = process.exitValue();
                String out = new String(buffer.toByteArray(), StandardCharsets.UTF_8);
                lastAttempt = new ExecResult(true, code, out);
                if (code == 0) return lastAttempt;
            } catch (Throwable ignored) {
                // Try the next known su location.
            } finally {
                if (process != null) {
                    try { process.getInputStream().close(); } catch (Throwable ignored) { }
                    try { process.getErrorStream().close(); } catch (Throwable ignored) { }
                    try { process.getOutputStream().close(); } catch (Throwable ignored) { }
                }
            }
        }
        return lastAttempt;
    }

    static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                  String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override public String getType(Uri uri) {
        return null;
    }

    @Override public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override public int update(Uri uri, ContentValues values, String selection,
                                String[] selectionArgs) {
        return 0;
    }
}
