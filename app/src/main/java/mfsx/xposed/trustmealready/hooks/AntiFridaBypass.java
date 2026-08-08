package mfsx.xposed.trustmealready.hooks;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.regex.Pattern;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import mfsx.xposed.trustmealready.HookHelper;

/**
 * Anti-Frida detection bypass - Java layer.
 *
 * <p>Bypasses the most common Java-level Frida detection techniques:
 * <ul>
 *   <li>/proc/self/maps scanning for frida/gum agents</li>
 *   <li>/proc/self/status TracerPid checking</li>
 *   <li>/proc/self/task thread name scanning (gum-js-loop, gmain)</li>
 *   <li>Runtime.exec() interception of ps/su commands</li>
 *   <li>PackageManager scanning for frida-related packages</li>
 *   <li>System.loadLibrary/load interception (hides our own gadget load)</li>
 *   <li>Socket port scanning (27042/27043 detection)</li>
 *   <li>/proc/net/tcp port 27042 (hex 69A2) LISTEN state filtering</li>
 * </ul>
 *
 * <p>Works with both Frida-Gadget and Frida-Server:
 * <ul>
 *   <li>Gadget mode: hides the loaded library (libtma.so) from detection</li>
 *   <li>Server mode: hides frida-server's port 27042, process name, and traces</li>
 * </ul>
 *
 * <p><b>SAFETY:</b> All hooks are surgically scoped - only intercept
 * Frida-related strings/paths, never global file or process operations.
 * Does NOT conflict with other Java-layer hooks (SSL, VPN, etc.).
 *
 * <p><b>PERFORMANCE:</b> Global hooks on BufferedReader.readLine and
 * File.exists/canRead were REMOVED - they intercepted every single call
 * in the app (thousands per second during startup), causing severe lag
 * and ANR. /proc filtering is handled by the Native-layer
 * anti_frida_detection.js script (hooks read() at the native level,
 * much lower overhead).
 */
public class AntiFridaBypass implements HookModule {

    /** Patterns that indicate Frida presence in /proc/maps or loaded libraries */
    private static final Pattern FRIDA_PATTERN = Pattern.compile(
            "frida|gum-js-loop|gmain|linjector|pool-frida|frida-agent|frida-gadget|frida-helper",
            Pattern.CASE_INSENSITIVE
    );

    @Override
    public String name() {
        return "Anti-Frida Detection Bypass";
    }

    @Override
    public void apply(HookHelper h) {
        // CONDITIONAL: Only register hooks when Frida is actually active.
        // When Frida-Gadget is not loaded and frida-server is not running,
        // there is nothing to hide - registering hooks on Socket.connect()
        // and System.load() would add overhead to every network connection
        // and library load for no benefit.
        if (!isFridaActive(h.packageName)) {
            XposedBridge.log("TrustMeAlready [" + h.packageName
                    + "] AntiFridaBypass: Frida not active, skipping (zero overhead)");
            return;
        }
        XposedBridge.log("TrustMeAlready [" + h.packageName
                + "] AntiFridaBypass: Frida active, registering hooks");
        hookRuntimeExec(h);
        hookSystemLoadLibrary(h);
        hookPackageManagerForFrida(h);
        hookSocketConnectFridaPort(h);
    }

    // ------------------------------------------------------------------
    // Check if Frida is active (Gadget flag file or frida-server running).
    // Runs ONCE at module registration time - zero per-call cost.
    // ------------------------------------------------------------------
    private boolean isFridaActive(String packageName) {
        // Check 1: Gadget opt-in flag file
        File flag1 = new File("/data/data/" + packageName, "tma_gadget_enable");
        if (flag1.exists()) return true;
        File flag2 = new File("/data/user/0/" + packageName, "tma_gadget_enable");
        if (flag2.exists()) return true;

        // Check 2: frida-server running (port 27042 = hex 69A2 in LISTEN state)
        String hexPort = Integer.toHexString(27042).toUpperCase();
        if (checkProcNetFile("/proc/net/tcp", hexPort)) return true;
        if (checkProcNetFile("/proc/net/tcp6", hexPort)) return true;

        return false;
    }

    private boolean checkProcNetFile(String path, String hexPort) {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(path));
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                if (lower.contains(":" + hexPort.toLowerCase()) && lower.contains(" 0a ")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            try { if (reader != null) reader.close(); } catch (Throwable ignored) {}
        }
        return false;
    }

    // ------------------------------------------------------------------
    // File.exists / File.canRead - hide Frida-related paths only
    // ------------------------------------------------------------------
    private void hookFileExistsForFridaPaths(HookHelper h) {
        final XC_MethodHook existsHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                try {
                    File file = (File) param.thisObject;
                    if (file == null) return;
                    String path = file.getAbsolutePath();
                    if (path == null) return;
                    // Only intercept paths containing frida/gum keywords
                    if (isFridaRelatedPath(path)) {
                        param.setResult(false);
                    }
                } catch (Throwable ignored) {
                }
            }
        };

        try {
            XposedHelpers.findAndHookMethod(File.class, "exists", existsHook);
            h.logHook("File.exists (anti-frida)");
        } catch (Throwable t) {
            h.logError("File.exists (anti-frida)", t);
        }

        try {
            XposedHelpers.findAndHookMethod(File.class, "canRead", existsHook);
            h.logHook("File.canRead (anti-frida)");
        } catch (Throwable t) {
            h.logError("File.canRead (anti-frida)", t);
        }
    }

    // ------------------------------------------------------------------
    // Runtime.exec - intercept commands that might detect Frida
    // ------------------------------------------------------------------
    private void hookRuntimeExec(HookHelper h) {
        XC_MethodHook execHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                try {
                    if (param.args == null || param.args.length == 0) return;
                    Object arg0 = param.args[0];
                    String cmd = null;
                    if (arg0 instanceof String) {
                        cmd = (String) arg0;
                    } else if (arg0 instanceof String[]) {
                        StringBuilder sb = new StringBuilder();
                        for (String s : (String[]) arg0) {
                            sb.append(s).append(" ");
                        }
                        cmd = sb.toString();
                    }
                    if (cmd == null) return;
                    // Block commands that scan for Frida
                    if (cmd.contains("frida") || cmd.contains("frida-server")
                            || cmd.contains("frida-agent") || cmd.contains("frida-gadget")) {
                        param.setResult(null);
                        return;
                    }
                    // Intercept "ps" commands that list processes
                    if (cmd.trim().startsWith("ps ") || cmd.trim().equals("ps")
                            || cmd.contains("ps aux") || cmd.contains("ps -A")) {
                        // Let it run but we'll filter the output via BufferedReader hook
                        return;
                    }
                    // Block "su -c" commands that check for frida
                    if (cmd.contains("su") && (cmd.contains("frida") || cmd.contains("27042"))) {
                        param.setResult(null);
                        return;
                    }
                    // Block "netstat" / "ss" checking for port 27042
                    if ((cmd.contains("netstat") || cmd.contains("ss ")) && cmd.contains("27042")) {
                        param.setResult(null);
                    }
                } catch (Throwable ignored) {
                }
            }
        };

        try {
            // Hook all Runtime.exec overloads
            for (java.lang.reflect.Method m : Runtime.class.getDeclaredMethods()) {
                if (m.getName().equals("exec")) {
                    try {
                        Class<?>[] paramTypes = m.getParameterTypes();
                        Object[] hookArgs = new Object[paramTypes.length + 1];
                        System.arraycopy(paramTypes, 0, hookArgs, 0, paramTypes.length);
                        hookArgs[paramTypes.length] = execHook;
                        XposedHelpers.findAndHookMethod(Runtime.class, "exec", hookArgs);
                        h.logHook("Runtime.exec (anti-frida)");
                    } catch (Throwable ignored) {
                    }
                }
            }
        } catch (Throwable t) {
            h.logError("Runtime.exec (anti-frida)", t);
        }
    }

    // ------------------------------------------------------------------
    // System.loadLibrary / System.load - block app's own frida detection
    // via library loading. Our gadget is loaded as "libtma.so" (no frida
    // keyword) so this hook won't interfere with our loading.
    // ------------------------------------------------------------------
    private void hookSystemLoadLibrary(HookHelper h) {
        XC_MethodHook loadHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                try {
                    if (param.args == null || param.args.length == 0) return;
                    Object arg0 = param.args[0];
                    if (arg0 == null) return;
                    String libName = arg0.toString();
                    // Only block if the APP tries to load a frida-detection
                    // library (not our gadget which is "libtma.so")
                    // We block the load to prevent the app from using the
                    // library's detection API
                    if (libName.contains("frida-detect") || libName.contains("antifrida")) {
                        param.setResult(null);
                    }
                    // Do NOT block "frida" or "gadget" in path - our own
                    // FridaController loads via System.load("/path/libtma.so")
                    // which doesn't contain these keywords.
                } catch (Throwable ignored) {
                }
            }
        };

        try {
            XposedHelpers.findAndHookMethod(System.class, "loadLibrary",
                    String.class, loadHook);
            h.logHook("System.loadLibrary (anti-frida)");
        } catch (Throwable t) {
            h.logError("System.loadLibrary (anti-frida)", t);
        }

        try {
            XposedHelpers.findAndHookMethod(System.class, "load",
                    String.class, loadHook);
            h.logHook("System.load (anti-frida)");
        } catch (Throwable t) {
            h.logError("System.load (anti-frida)", t);
        }
    }

    // ------------------------------------------------------------------
    // Process.myPid TracerPid check via /proc/self/status
    // The BufferedReader.readLine hook already covers filtering TracerPid
    // lines, so this method is a no-op placeholder for future expansion.
    // ------------------------------------------------------------------
    private void hookProcessMyPidTracerCheck(HookHelper h) {
        // TracerPid filtering is handled by hookBufferedReaderForMaps()
        // which intercepts all readLine() calls and fixes TracerPid values.
        // No additional hooks needed here.
    }

    // ------------------------------------------------------------------
    // PackageManager.getInstalledApplications - hide Frida-related packages
    // ------------------------------------------------------------------
    private void hookPackageManagerForFrida(HookHelper h) {
        try {
            Class<?> pmClass = h.findClass("android.content.pm.PackageManager");
            if (pmClass == null) return;

            XC_MethodHook pmHook = new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        Object result = param.getResult();
                        if (result == null) return;
                        if (result instanceof java.util.List) {
                            java.util.List<?> list = (java.util.List<?>) result;
                            java.util.Iterator<?> it = list.iterator();
                            while (it.hasNext()) {
                                Object info = it.next();
                                try {
                                    Object appInfo = XposedHelpers.getObjectField(info, "applicationInfo");
                                    String pkgName = (String) XposedHelpers.getObjectField(appInfo, "packageName");
                                    if (pkgName != null && (pkgName.contains("frida")
                                            || pkgName.contains("re.frida"))) {
                                        it.remove();
                                    }
                                } catch (Throwable ignored) {
                                }
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            };

            // Hook getInstalledApplications(int flags)
            XposedHelpers.findAndHookMethod(pmClass, "getInstalledApplications",
                    int.class, pmHook);
            h.logHook("PackageManager.getInstalledApplications (anti-frida)");
        } catch (Throwable t) {
            h.logError("PackageManager.getInstalledApplications (anti-frida)", t);
        }
    }

    // ------------------------------------------------------------------
    // Socket.connect - block connections to port 27042 (frida detection probe)
    // ------------------------------------------------------------------
    private void hookSocketConnectFridaPort(HookHelper h) {
        try {
            Class<?> inetAddrClass = h.findClass("java.net.InetSocketAddress");
            if (inetAddrClass == null) return;

            XC_MethodHook socketHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.args == null || param.args.length == 0) return;
                        Object addr = param.args[0];
                        if (addr instanceof java.net.InetSocketAddress) {
                            java.net.InetSocketAddress inetAddr = (java.net.InetSocketAddress) addr;
                            int port = inetAddr.getPort();
                            if (port == 27042 || port == 27043) {
                                // Redirect to a dead port to make the probe fail gracefully
                                param.setResult(null);
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            };

            XposedHelpers.findAndHookMethod(java.net.Socket.class, "connect",
                    java.net.SocketAddress.class, int.class, socketHook);
            h.logHook("Socket.connect (anti-frida port)");

            XposedHelpers.findAndHookMethod(java.net.Socket.class, "connect",
                    java.net.SocketAddress.class, socketHook);
            h.logHook("Socket.connect (anti-frida port 2)");
        } catch (Throwable t) {
            h.logError("Socket.connect (anti-frida)", t);
        }
    }

    // ------------------------------------------------------------------
    // BufferedReader.readLine - filter Frida traces from /proc/maps and status
    // PERFORMANCE: Fast path - only check lines containing ':' or '/' (proc
    // file format). Skip all other lines without any pattern matching.
    // ------------------------------------------------------------------
    private void hookBufferedReaderForMaps(HookHelper h) {
        try {
            XC_MethodHook readLineHook = new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        Object result = param.getResult();
                        if (result == null) return;
                        // Fast path: only check lines with ':' or '/' (proc format)
                        // This avoids checking every single line read by the app
                        String line = (String) result;
                        if (line.indexOf(':') == -1 && line.indexOf('/') == -1) {
                            return; // Not a proc file line, skip
                        }
                        // Check for TracerPid (most common check)
                        if (line.contains("TracerPid:")) {
                            String val = line.substring(line.indexOf("TracerPid:") + 10).trim();
                            if (!val.equals("0")) {
                                param.setResult("TracerPid:\t0\n");
                            }
                            return;
                        }
                        // Check for frida in /proc/maps lines (contain paths)
                        if (line.length() > 20) {
                            String lower = line.toLowerCase();
                            if (lower.contains("frida") || lower.contains("gum-js")
                                    || lower.contains("linjector") || lower.contains("pool-frida")) {
                                param.setResult("\n"); // Replace with blank line
                                return;
                            }
                            // Check for frida-server port in /proc/net/tcp
                            // Port 27042 = 0x69A2, Port 27043 = 0x69A3
                            // /proc/net/tcp lines: "  0: 0100007F:69A2 00000000:0000 0A ..."
                            // State 0A = LISTEN
                            if ((lower.contains(":69a2") || lower.contains(":69a3"))
                                    && lower.contains(" 0a ")) {
                                param.setResult("\n"); // Hide this listening port
                                return;
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            };

            XposedHelpers.findAndHookMethod(BufferedReader.class, "readLine", readLineHook);
            h.logHook("BufferedReader.readLine (anti-frida)");
        } catch (Throwable t) {
            h.logError("BufferedReader.readLine (anti-frida)", t);
        }
    }

    // ------------------------------------------------------------------
    // Helper: check if path is Frida-related
    // ------------------------------------------------------------------
    private boolean isFridaRelatedPath(String path) {
        if (path == null) return false;
        return path.contains("frida") || path.contains("re.frida")
                || path.contains("frida-server") || path.contains("frida-agent")
                || path.contains("frida-gadget") || path.contains("linjector")
                || path.contains("pool-frida") || path.contains("gum-js-loop");
    }

    // ------------------------------------------------------------------
    // Helper: check if a line from /proc/maps or /proc/status is Frida-related
    // ------------------------------------------------------------------
    private boolean isFridaRelatedLine(String line) {
        if (line == null) return false;
        return FRIDA_PATTERN.matcher(line).find();
    }
}
