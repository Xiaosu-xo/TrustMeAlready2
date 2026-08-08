package mfsx.xposed.trustmealready;

import android.content.res.AssetManager;

import org.tukaani.xz.XZInputStream;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

/**
 * Frida injection controller - dual-mode (Gadget auto-injection + Frida-Server).
 *
 * <p>LSPosed calls this module when the target app loads. It supports two modes:
 *
 * <p><b>Mode A - Frida-Server (detected at startup):</b><br>
 * If frida-server is already running on the device (port 27042 in LISTEN state
 * or frida-server process found in /proc), the controller:
 * <ol>
 *   <li>Extracts Frida scripts to the app's data directory</li>
 *   <li>Skips gadget download/loading (frida-server and gadget CANNOT coexist)</li>
 *   <li>Logs instructions for using <code>frida -U -f &lt;package&gt;</code></li>
 * </ol>
 *
 * <p><b>Mode B - Frida-Gadget opt-in injection:</b><br>
 * If frida-server is NOT running, the controller checks for an opt-in flag
 * file at <code>/data/data/&lt;pkg&gt;/tma_gadget_enable</code>. Gadget loading
 * is <b>DISABLED by default</b> because Frida's native hooks on open()/read()/
 * close()/connect() add overhead to every system call, causing app freeze.
 * <ul>
 *   <li><b>No flag file (default):</b> Scripts extracted, gadget NOT loaded.
 *       Java-layer hooks remain active for SSL pinning bypass and packet capture.</li>
 *   <li><b>Flag file exists:</b> Gadget is loaded via System.load() with all
 *       native/framework bypass scripts. Use only when Java hooks are insufficient
 *       (e.g., Flutter, React Native apps with native SSL pinning).</li>
 * </ul>
 * To enable: <code>adb shell "touch /data/data/&lt;package&gt;/tma_gadget_enable"</code>
 *
 * <p><b>Anti-detection:</b> The AntiFridaBypass module (registered separately in
 * Main.java) hooks Java-layer Frida detection before this controller runs,
 * preventing detection of both frida-server and frida-gadget.
 *
 * <p><b>No conflict with Java hooks:</b> Frida (gadget or server) operates at
 * the Native layer (SSL_get_error, SSL_CTX_set_verify, etc.), while LSPosed
 * hooks operate at the Java layer (TrustManager, SSLContext.init, etc.).
 * They target different layers of the stack and do not interfere.
 */
public final class FridaController {

    private static final String TAG = "TrustMeAlready [Frida] ";
    private static final String ASSET_DIR = "frida";
    private static final String GADGET_CONFIG_ASSET = "frida-gadget/config.json";
    private static final String GADGET_DIR_NAME = "tma_gadget";
    private static final String SCRIPT_DIR_NAME = "tma_frida_scripts";

    // Frida-Gadget version - must match the bundled jniLibs version
    private static final String GADGET_VERSION = "17.17.0";

    // GitHub release download URL template
    private static final String GADGET_URL_TEMPLATE =
            "https://github.com/frida/frida/releases/download/%s/frida-gadget-%s-android-%s.so.xz";

    private static final String[] SCRIPTS = {
            "native_ssl_bypass.js",
            "flutter_bypass.js",
            "react_native_bypass.js",
            "cordova_bypass.js",
            "hybrid_framework_bypass.js",
            "anti_frida_detection.js"
    };

    private final LoadPackageParam lpparam;
    private final String packageName;

    public FridaController(LoadPackageParam lpparam) {
        this.lpparam = lpparam;
        this.packageName = lpparam.packageName;
    }

    /**
     * Initialize Frida-Gadget injection in a background thread.
     * Safe to call from any thread - does not block app startup.
     */
    public void init() {
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                doInit();
            }
        }, "TMA-FridaController");
        t.setDaemon(true);
        t.start();
    }

    private void doInit() {
        try {
            // Step 1: Determine the app's data directory
            String dataDir = getTargetDataDir();
            if (dataDir == null) {
                log("Could not determine target app data directory, skipping");
                return;
            }

            // Step 2: Create script directory and extract scripts (needed for both modes)
            File scriptDir = new File(dataDir, SCRIPT_DIR_NAME);
            if (!scriptDir.exists() && !scriptDir.mkdirs()) {
                log("Failed to create script directory");
                return;
            }

            String moduleApkPath = findModuleApkPath();
            if (moduleApkPath != null) {
                extractScripts(moduleApkPath, scriptDir);
            }

            // Step 3: Check if frida-server is already running.
            // frida-server and frida-gadget CANNOT coexist - both use the
            // Frida core (gum.js). Loading gadget while frida-server is
            // attached will crash the process.
            if (isFridaServerRunning()) {
                log("=== FRIDA-SERVER DETECTED (port 27042) ===");
                log("frida-server is running on this device.");
                log("Gadget injection SKIPPED to avoid conflict.");
                log("");
                log("Scripts extracted to: " + scriptDir.getAbsolutePath());
                log("");
                log("Use frida-server for interactive debugging:");
                log("  frida -U -f " + packageName + " \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/native_ssl_bypass.js \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/flutter_bypass.js \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/react_native_bypass.js \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/cordova_bypass.js \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/hybrid_framework_bypass.js \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/anti_frida_detection.js \\");
                log("    --no-pause");
                log("");
                log("AntiFridaBypass Java hooks are ACTIVE (hiding frida-server).");
                log("=== FRIDA-SERVER MODE ACTIVE ===");
                return;
            }

            log("frida-server NOT detected.");

            // Step 3b: Check for opt-in flag file.
            // Frida-Gadget loading is DISABLED by default because:
            //   1. Frida's Interceptor.attach() on open()/read()/close()/
            //      connect() adds a trampoline to EVERY system call (thousands
            //      per second), causing severe lag and ANR (app freeze).
            //   2. native_ssl_bypass.js hooks SSL functions at the native
            //      level, conflicting with Java-layer SSLPinningBypass hooks
            //      and breaking network connections (can't capture packets).
            //
            // To enable gadget loading:
            //   adb shell "touch /data/data/<package>/tma_gadget_enable"
            //   (requires root)
            File gadgetFlag = new File(dataDir, "tma_gadget_enable");
            if (!gadgetFlag.exists()) {
                log("=== GADGET AUTO-INJECTION DISABLED (default) ===");
                log("Frida-Gadget is NOT loaded to prevent app freeze.");
                log("Java-layer hooks (SSL, VPN, debugger, etc.) are ACTIVE.");
                log("Packet capture should work normally.");
                log("");
                log("Scripts extracted to: " + scriptDir.getAbsolutePath());
                log("");
                log("To enable Gadget (may cause performance issues):");
                log("  adb shell \"touch /data/data/" + packageName + "/tma_gadget_enable\"");
                log("  (requires root, then restart target app)");
                log("");
                log("Or use frida-server for interactive debugging:");
                log("  frida -U -f " + packageName + " \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/native_ssl_bypass.js \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/flutter_bypass.js \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/react_native_bypass.js \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/cordova_bypass.js \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/hybrid_framework_bypass.js \\");
                log("    -l " + scriptDir.getAbsolutePath() + "/anti_frida_detection.js \\");
                log("    --no-pause");
                log("=== GADGET DISABLED - JAVA HOOKS ONLY ===");
                return;
            }

            log("Gadget opt-in flag detected. Proceeding with gadget injection...");

            // Step 4: Detect CPU architecture
            String arch = detectArch();
            if (arch == null) {
                log("Unsupported CPU architecture, skipping gadget injection");
                log("Manual option: start frida-server and use 'frida -U -f " + packageName + "'");
                return;
            }
            log("Detected architecture: " + arch);

            // Step 5: Create gadget directory (writable - for .so + config)
            File gadgetDir = new File(dataDir, GADGET_DIR_NAME);
            if (!gadgetDir.exists() && !gadgetDir.mkdirs()) {
                log("Failed to create gadget directory");
                return;
            }

            // Step 6: Create libtma.config in gadget directory.
            // frida-gadget looks for a config file named {soname}.config
            // (i.e., "libtma.config") in the SAME directory as the .so.
            // If not found, gadget defaults to "listen" mode (waits for
            // frida client, no scripts loaded, app appears stuck).
            // We use absolute path to the script directory.
            File gadgetConfig = new File(gadgetDir, "libtma.config");
            String scriptAbsPath = new File(dataDir, SCRIPT_DIR_NAME).getAbsolutePath();
            String configJson = "{\n"
                    + "  \"interaction\": {\n"
                    + "    \"type\": \"script-directory\",\n"
                    + "    \"path\": \"" + scriptAbsPath + "\",\n"
                    + "    \"on_change\": \"rescan\"\n"
                    + "  },\n"
                    + "  \"teardown\": \"full\"\n"
                    + "}";
            try {
                FileOutputStream fos = new FileOutputStream(gadgetConfig);
                fos.write(configJson.getBytes());
                fos.close();
                log("Created gadget config: " + gadgetConfig.getAbsolutePath());
            } catch (Throwable t) {
                log("Failed to create gadget config: " + t.getMessage());
            }

            // Step 7: The gadget .so must be in the SAME directory as the
            // config file. The module's nativeLibraryDir is read-only, so
            // we copy the bundled libtma.so to the gadget directory.
            File gadgetSo = new File(gadgetDir, "libtma.so");

            // Step 7a: If already cached in gadget dir, use it
            if (gadgetSo.exists() && gadgetSo.length() > 100000) {
                log("Using cached gadget: " + gadgetSo.getAbsolutePath()
                        + " (" + (gadgetSo.length() / 1024 / 1024) + " MB)");
            } else {
                // Step 7b: Try to copy from module's bundled jniLibs
                String moduleLibDir = findModuleNativeLibDir();
                boolean found = false;
                if (moduleLibDir != null) {
                    File bundled = new File(moduleLibDir, "libtma.so");
                    if (bundled.exists() && bundled.length() > 100000) {
                        log("Copying bundled libtma.so (" + (bundled.length() / 1024 / 1024)
                                + " MB) to " + gadgetSo.getAbsolutePath());
                        if (copyFile(bundled, gadgetSo)) {
                            log("Copy successful");
                            found = true;
                        } else {
                            log("Copy failed, trying direct load from module lib dir");
                            // Fall back to loading directly (config won't be found,
                            // but at least the gadget loads)
                            gadgetSo = bundled;
                            found = true;
                        }
                    }
                }

                // Step 7c: If not bundled, download as fallback
                if (!found) {
                    log("Gadget not bundled, downloading (fallback)...");
                    boolean ok = downloadAndDecompressGadget(arch, gadgetSo);
                    if (!ok) {
                        log("Download failed. Native/Framework bypass will not work.");
                        log("Fallback: start frida-server and use 'frida -U -f " + packageName + "'");
                        return;
                    }
                }
            }

            // Step 8: Load the gadget via System.load()
            // AntiFridaBypass hooks are already in place to hide this
            try {
                log("Loading gadget: " + gadgetSo.getAbsolutePath());
                System.load(gadgetSo.getAbsolutePath());
                log("Frida-Gadget v" + GADGET_VERSION + " loaded successfully!");
                log("Gadget config: " + gadgetConfig.getAbsolutePath());
                log("Scripts dir: " + scriptAbsPath);
            } catch (UnsatisfiedLinkError e) {
                log("Failed to load gadget (architecture mismatch?): " + e.getMessage());
                gadgetSo.delete();
                log("Fallback: start frida-server and use 'frida -U -f " + packageName + "'");
            } catch (Throwable t) {
                log("Error loading gadget: " + t.getMessage());
            }

        } catch (Throwable t) {
            log("Init failed: " + t.getMessage());
        }
    }

    // ------------------------------------------------------------------
    // Check if frida-server is running on the device.
    //
    // frida-server and frida-gadget CANNOT coexist in the same process.
    // If frida-server is detected, we skip gadget loading to avoid crashes.
    //
    // Detection methods:
    //   1. Parse /proc/net/tcp for port 27042 (hex: 69A2) in LISTEN state
    //   2. Scan /proc/*/cmdline for "frida-server" process (rooted devices)
    // ------------------------------------------------------------------
    private boolean isFridaServerRunning() {
        // Method 1: Parse /proc/net/tcp for frida-server port (27042 = 0x69A2)
        if (checkPortInProcNet("27042")) return true;
        // Also check alternate port 27043 = 0x69A3
        if (checkPortInProcNet("27043")) return true;

        // Method 2: Scan /proc for frida-server process name (works on rooted devices)
        if (checkProcForFridaServer()) return true;

        return false;
    }

    /**
     * Check if a specific port is listening by parsing /proc/net/tcp and /proc/net/tcp6.
     * Port is checked in hex format (e.g., "27042" ? "69A2").
     */
    private boolean checkPortInProcNet(String portStr) {
        String hexPort = Integer.toHexString(Integer.parseInt(portStr)).toUpperCase();

        // Check /proc/net/tcp (IPv4)
        if (checkProcNetFile("/proc/net/tcp", hexPort)) return true;
        // Check /proc/net/tcp6 (IPv6)
        if (checkProcNetFile("/proc/net/tcp6", hexPort)) return true;

        return false;
    }

    private boolean checkProcNetFile(String path, String hexPort) {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(path));
            String line;
            while ((line = reader.readLine()) != null) {
                try {
                    String lower = line.toLowerCase();
                    // /proc/net/tcp format:
                    //   sl  local_address  rem_address  st  ...
                    //   0:  0100007F:69A2  00000000:0000  0A  ...
                    // State 0A = LISTEN
                    if (lower.contains(":" + hexPort.toLowerCase()) && lower.contains(" 0a ")) {
                        return true;
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        } finally {
            try { if (reader != null) reader.close(); } catch (Throwable ignored) {}
        }
        return false;
    }

    /**
     * Scan /proc for frida-server process name (check cmdline of each PID).
     * Only works on rooted devices where /proc is world-readable.
     */
    private boolean checkProcForFridaServer() {
        try {
            File procDir = new File("/proc");
            File[] processDirs = procDir.listFiles();
            if (processDirs == null) return false;

            for (File proc : processDirs) {
                try {
                    if (!proc.isDirectory()) continue;
                    String name = proc.getName();
                    // Skip non-numeric entries
                    if (name == null || name.length() == 0 || !Character.isDigit(name.charAt(0))) {
                        continue;
                    }

                    File cmdline = new File(proc, "cmdline");
                    if (!cmdline.exists() || !cmdline.canRead()) continue;

                    // Read cmdline (null-separated args)
                    FileInputStream fis = new FileInputStream(cmdline);
                    byte[] buf = new byte[512];
                    int len = fis.read(buf);
                    fis.close();
                    if (len > 0) {
                        String cmd = new String(buf, 0, len).trim();
                        // cmdline uses \0 as separator; take first arg
                        int nul = cmd.indexOf('\0');
                        if (nul > 0) cmd = cmd.substring(0, nul);
                        // Check for frida-server / frida_server process
                        cmd = cmd.toLowerCase();
                        if (cmd.contains("frida-server") || cmd.contains("frida_server")
                                || (cmd.contains("frida") && cmd.endsWith("server"))) {
                            return true;
                        }
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Detect CPU architecture from Build.CPU_ABI
    // ------------------------------------------------------------------
    private String detectArch() {
        try {
            // Use Build.CPU_ABI (deprecated but works on all API levels)
            String cpuAbi = (String) XposedHelpers.getStaticObjectField(
                    android.os.Build.class, "CPU_ABI");
            if (cpuAbi == null) {
                cpuAbi = (String) XposedHelpers.getStaticObjectField(
                        android.os.Build.class, "CPU_ABI2");
            }
            if (cpuAbi == null) {
                // Try Build.SUPPORTED_ABIS (API 21+)
                try {
                    String[] abis = (String[]) XposedHelpers.getStaticObjectField(
                            android.os.Build.VERSION.class, "SUPPORTED_ABIS");
                    if (abis != null && abis.length > 0) {
                        cpuAbi = abis[0];
                    }
                } catch (Throwable ignored) {
                }
            }

            if (cpuAbi == null) return null;

            if (cpuAbi.contains("arm64")) return "arm64";
            if (cpuAbi.contains("armeabi")) return "arm";
            if (cpuAbi.contains("x86_64")) return "x86_64";
            if (cpuAbi.contains("x86")) return "x86";

            return null;
        } catch (Throwable t) {
            log("Architecture detection failed: " + t.getMessage());
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Download frida-gadget.so.xz and decompress using org.tukaani:xz
    // ------------------------------------------------------------------
    private boolean downloadAndDecompressGadget(String arch, File outputFile) {
        String url = String.format(GADGET_URL_TEMPLATE, GADGET_VERSION, GADGET_VERSION, arch);
        log("Downloading from: " + url);

        File xzFile = new File(outputFile.getParentFile(), "gadget.so.xz");
        HttpURLConnection conn = null;
        InputStream is = null;
        OutputStream os = null;

        try {
            // Download the .xz file
            URL downloadUrl = new URL(url);
            conn = (HttpURLConnection) downloadUrl.openConnection();
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(60000);
            conn.setRequestProperty("User-Agent", "TrustMeAlready/2.0");
            conn.setInstanceFollowRedirects(true);

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                log("Download failed: HTTP " + responseCode);
                return false;
            }

            is = conn.getInputStream();
            os = new FileOutputStream(xzFile);
            byte[] buffer = new byte[8192];
            int read;
            long total = 0;
            while ((read = is.read(buffer)) != -1) {
                os.write(buffer, 0, read);
                total += read;
            }
            os.flush();
            os.close();
            os = null;
            log("Downloaded " + (total / 1024) + " KB");

            // Decompress .xz using org.tukaani:xz
            return decompressXz(xzFile, outputFile);

        } catch (Throwable t) {
            log("Download/decompress error: " + t.getMessage());
            return false;
        } finally {
            try { if (is != null) is.close(); } catch (Throwable ignored) {}
            try { if (os != null) os.close(); } catch (Throwable ignored) {}
            if (conn != null) conn.disconnect();
            // Clean up .xz file
            xzFile.delete();
        }
    }

    // ------------------------------------------------------------------
    // Decompress .xz file using org.tukaani:xz XZInputStream
    // ------------------------------------------------------------------
    private boolean decompressXz(File xzFile, File outputFile) {
        FileInputStream fis = null;
        XZInputStream xzis = null;
        FileOutputStream fos = null;

        try {
            fis = new FileInputStream(xzFile);
            xzis = new XZInputStream(fis);
            fos = new FileOutputStream(outputFile);

            byte[] buffer = new byte[8192];
            int read;
            long total = 0;
            while ((read = xzis.read(buffer)) != -1) {
                fos.write(buffer, 0, read);
                total += read;
            }
            fos.flush();
            log("Decompressed " + (total / 1024 / 1024) + " MB");
            return true;

        } catch (Throwable t) {
            log("XZ decompression error: " + t.getMessage());
            return false;
        } finally {
            try { if (xzis != null) xzis.close(); } catch (Throwable ignored) {}
            try { if (fis != null) fis.close(); } catch (Throwable ignored) {}
            try { if (fos != null) fos.close(); } catch (Throwable ignored) {}
        }
    }

    // ------------------------------------------------------------------
    // Extract Frida scripts from module APK assets
    // ------------------------------------------------------------------
    private void extractScripts(String apkPath, File outDir) {
        AssetManager am = createAssetManager(apkPath);
        if (am == null) {
            log("Could not create AssetManager for script extraction");
            return;
        }

        int count = 0;
        for (String script : SCRIPTS) {
            String assetPath = ASSET_DIR + "/" + script;
            File outFile = new File(outDir, script);
            if (extractAsset(am, assetPath, outFile)) {
                count++;
            }
        }

        try { am.close(); } catch (Throwable ignored) {}
        log("Extracted " + count + " Frida scripts to " + outDir.getAbsolutePath());
    }

    // ------------------------------------------------------------------
    // Extract gadget config from module APK assets
    // ------------------------------------------------------------------
    private void extractGadgetConfig(String apkPath, File gadgetDir) {
        AssetManager am = createAssetManager(apkPath);
        if (am == null) return;

        File configFile = new File(gadgetDir, "config.json");
        if (!extractAsset(am, GADGET_CONFIG_ASSET, configFile)) {
            // Create a default config if asset not found
            createDefaultConfig(configFile, gadgetDir);
        }

        try { am.close(); } catch (Throwable ignored) {}
    }

    // ------------------------------------------------------------------
    // Create default gadget config (script-directory interaction mode)
    // ------------------------------------------------------------------
    private void createDefaultConfig(File configFile, File gadgetDir) {
        String config = "{\n"
                + "  \"interaction\": {\n"
                + "    \"type\": \"script-directory\",\n"
                + "    \"path\": \"" + gadgetDir.getParent() + "/" + SCRIPT_DIR_NAME + "\",\n"
                + "    \"on_change\": \"rescan\"\n"
                + "  }\n"
                + "}";
        try {
            FileOutputStream fos = new FileOutputStream(configFile);
            fos.write(config.getBytes());
            fos.close();
            log("Created default gadget config at " + configFile.getAbsolutePath());
        } catch (IOException e) {
            log("Failed to create default config: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------
    // AssetManager helpers
    // ------------------------------------------------------------------
    private AssetManager createAssetManager(String apkPath) {
        try {
            AssetManager am = AssetManager.class.newInstance();
            Method addAssetPath = AssetManager.class.getMethod("addAssetPath", String.class);
            Object result = addAssetPath.invoke(am, apkPath);
            if (result instanceof Integer && (Integer) result != 0) {
                return am;
            }
        } catch (Throwable t) {
            log("Error creating AssetManager: " + t.getMessage());
        }
        return null;
    }

    private boolean extractAsset(AssetManager am, String assetPath, File outFile) {
        InputStream is = null;
        OutputStream os = null;
        try {
            is = am.open(assetPath);
            os = new FileOutputStream(outFile);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                os.write(buffer, 0, read);
            }
            os.flush();
            return true;
        } catch (IOException e) {
            return false;
        } catch (Throwable t) {
            return false;
        } finally {
            try { if (is != null) is.close(); } catch (Throwable ignored) {}
            try { if (os != null) os.close(); } catch (Throwable ignored) {}
        }
    }

    // ------------------------------------------------------------------
    // Find module APK path
    // ------------------------------------------------------------------
    private String findModuleApkPath() {
        // Try direct paths first
        for (int i = 1; i <= 4; i++) {
            String path = "/data/app/mfsx.xposed.trustmealready-" + i + "/base.apk";
            if (new File(path).exists()) return path;
        }

        String path = "/data/app/mfsx.xposed.trustmealready/base.apk";
        if (new File(path).exists()) return path;

        // Try scanning /data/app for directories containing the package name
        File dataApp = new File("/data/app");
        if (dataApp.exists() && dataApp.canRead()) {
            File[] dirs = dataApp.listFiles();
            if (dirs != null) {
                for (File dir : dirs) {
                    if (dir.getName().contains("trustmealready")) {
                        File apk = new File(dir, "base.apk");
                        if (apk.exists()) return apk.getAbsolutePath();
                    }
                }
            }
        }

        return null;
    }

    // ------------------------------------------------------------------
    // Find the module's native library directory.
    // When the APK is installed with useLegacyPackaging=true, the system
    // extracts lib/<arch>/libtma.so to this directory at install time.
    // We use the target app's PackageManager to look up the module's
    // ApplicationInfo.nativeLibraryDir.
    // ------------------------------------------------------------------
    private String findModuleNativeLibDir() {
        try {
            Class<?> activityThreadClass = XposedHelpers.findClass(
                    "android.app.ActivityThread", lpparam.classLoader);
            Object activityThread = XposedHelpers.callStaticMethod(
                    activityThreadClass, "currentActivityThread");
            if (activityThread == null) return null;

            Method getApplication = activityThreadClass.getMethod("getApplication");
            Object app = getApplication.invoke(activityThread);
            if (app == null) return null;

            android.content.Context context = (android.content.Context) app;
            android.content.pm.PackageManager pm = context.getPackageManager();

            try {
                android.content.pm.ApplicationInfo moduleInfo =
                        pm.getApplicationInfo("mfsx.xposed.trustmealready", 0);
                String nativeLibDir = (String) XposedHelpers.getObjectField(
                        moduleInfo, "nativeLibraryDir");
                if (nativeLibDir != null) {
                    File dir = new File(nativeLibDir);
                    if (dir.exists() && dir.canRead()) {
                        return nativeLibDir;
                    }
                }
            } catch (Throwable ignored) {
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Copy a file (used to copy bundled .so to writable directory)
    // ------------------------------------------------------------------
    private boolean copyFile(File src, File dst) {
        FileInputStream fis = null;
        FileOutputStream fos = null;
        try {
            fis = new FileInputStream(src);
            fos = new FileOutputStream(dst);
            byte[] buffer = new byte[65536];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                fos.write(buffer, 0, read);
            }
            fos.flush();
            return true;
        } catch (Throwable t) {
            log("Copy error: " + t.getMessage());
            return false;
        } finally {
            try { if (fis != null) fis.close(); } catch (Throwable ignored) {}
            try { if (fos != null) fos.close(); } catch (Throwable ignored) {}
        }
    }

    // ------------------------------------------------------------------
    // Get target app's data directory
    // ------------------------------------------------------------------
    private String getTargetDataDir() {
        try {
            Class<?> activityThreadClass = XposedHelpers.findClass(
                    "android.app.ActivityThread", lpparam.classLoader);
            Object activityThread = XposedHelpers.callStaticMethod(
                    activityThreadClass, "currentActivityThread");
            if (activityThread == null) return null;

            try {
                Method getApplication = activityThreadClass.getMethod("getApplication");
                Object app = getApplication.invoke(activityThread);
                if (app != null) {
                    File dataDir = (File) XposedHelpers.callMethod(app, "getDataDir");
                    if (dataDir != null) return dataDir.getAbsolutePath();
                }
            } catch (Throwable ignored) {
            }
        } catch (Throwable ignored) {
        }

        // Fallback to standard paths
        String[] possiblePaths = {
                "/data/data/" + packageName,
                "/data/user/0/" + packageName
        };

        for (String p : possiblePaths) {
            if (new File(p).exists()) return p;
        }

        return null;
    }

    private void log(String msg) {
        XposedBridge.log(TAG + "[" + packageName + "] " + msg);
    }
}
