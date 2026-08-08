package mfsx.xposed.trustmealready;

import java.util.ArrayList;
import java.util.List;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;
import mfsx.xposed.trustmealready.hooks.AntiFridaBypass;
import mfsx.xposed.trustmealready.hooks.DebuggerBypass;
import mfsx.xposed.trustmealready.hooks.DeveloperOptionsBypass;
import mfsx.xposed.trustmealready.hooks.EmulatorBypass;
import mfsx.xposed.trustmealready.hooks.HookModule;
import mfsx.xposed.trustmealready.hooks.NetworkSecurityBypass;
import mfsx.xposed.trustmealready.hooks.ProxyBypass;
import mfsx.xposed.trustmealready.hooks.SafetyNetBypass;
import mfsx.xposed.trustmealready.hooks.SSLPinningBypass;
import mfsx.xposed.trustmealready.hooks.UserCertificateBypass;
import mfsx.xposed.trustmealready.hooks.VPNBypass;

/**
 * TrustMeAlready v2.1 - Comprehensive Security Bypass Module
 *
 * <p>LSPosed handles the Java-layer bypass (SSL pinning, VPN/proxy detection,
 * developer options, debugger, emulator, user certificate, network security
 * config, SafetyNet/Play Integrity, anti-Frida detection). FridaController
 * provides dual-mode Native/Framework bypass:
 * <ul>
 *   <li><b>Mode A (Frida-Server):</b> If frida-server is running (port 27042),
 *       scripts are extracted and the user connects via <code>frida -U</code></li>
 *   <li><b>Mode B (Frida-Gadget, opt-in):</b> If no server is detected AND the
 *       flag file <code>tma_gadget_enable</code> exists in the app's data dir,
 *       gadget is loaded via System.load(). <b>Disabled by default</b> to
 *       prevent app freeze - native hooks on open()/read()/close() add overhead
 *       to every system call. Java-layer hooks alone are sufficient for most
 *       apps and packet capture.</li>
 * </ul>
 *
 * <p>Compatibility: Android 5.0 (API 21) through Android 16 (API 36).
 */
public class Main implements IXposedHookLoadPackage {

    private static final int MIN_API = 21;   // Android 5.0
    private static final int MAX_API = 36;   // Android 16

    @Override
    public void handleLoadPackage(final LoadPackageParam lpparam) {
        String packageName = lpparam.packageName;

        // Skip the module's own package and system server
        if ("mfsx.xposed.trustmealready".equals(packageName)) return;
        if ("android".equals(packageName)) return;

        int apiLevel = android.os.Build.VERSION.SDK_INT;
        XposedBridge.log("TrustMeAlready v2.8 loading: " + packageName
                + " (API " + apiLevel + ")");

        // API range check
        if (apiLevel < MIN_API) {
            XposedBridge.log("TrustMeAlready: API " + apiLevel
                    + " below minimum (" + MIN_API + "), skipping");
            return;
        }
        if (apiLevel > MAX_API) {
            XposedBridge.log("TrustMeAlready: API " + apiLevel
                    + " above tested maximum (" + MAX_API + "), proceeding with caution");
        }

        // --- Phase 1: Java-layer hooks (LSPosed) ---
        // All 9 modules enabled. Freeze issues fixed:
        //   1. SystemProperties.get() - was hooked TWICE (EmulatorBypass +
        //      DeveloperOptionsBypass). Fixed: ro.kernel.qemu merged into
        //      DeveloperOptionsBypass, EmulatorBypass no longer hooks it.
        //   2. AntiFridaBypass - was always registering hooks on Socket.connect()
        //      and System.load(). Fixed: now conditional - only registers when
        //      Frida is active (Gadget flag file or frida-server detected).
        //   3. Runtime.exec() - hooked by both AntiFridaBypass and VPNBypass.
        //      Acceptable: exec() is rarely called, overhead is negligible.
        HookHelper helper = new HookHelper(lpparam);

        List<HookModule> modules = new ArrayList<>();
        modules.add(new SSLPinningBypass());
        modules.add(new VPNBypass());
        // ProxyBypass DISABLED - hides system proxy, breaks packet capture
        // modules.add(new ProxyBypass());
        modules.add(new DeveloperOptionsBypass());
        modules.add(new DebuggerBypass());
        modules.add(new EmulatorBypass());
        modules.add(new UserCertificateBypass());
        modules.add(new NetworkSecurityBypass());
        modules.add(new SafetyNetBypass());
        // AntiFridaBypass: conditionally registers hooks only when Frida
        // is active. Zero overhead when Frida-Gadget is not loaded.
        modules.add(new AntiFridaBypass());

        int moduleSuccess = 0;
        int moduleFailure = 0;

        for (HookModule module : modules) {
            try {
                XposedBridge.log("TrustMeAlready [" + packageName + "] Applying: "
                        + module.name());
                module.apply(helper);
                moduleSuccess++;
            } catch (Throwable t) {
                XposedBridge.log("TrustMeAlready [" + packageName + "] Module failed: "
                        + module.name() + " - " + t.getMessage());
                moduleFailure++;
            }
        }

        XposedBridge.log("TrustMeAlready [" + packageName + "] Java hooks done: "
                + moduleSuccess + " ok, " + moduleFailure + " failed, "
                + helper.hookedMethods + " methods hooked, "
                + helper.errors + " errors (API " + apiLevel + ")");

        // --- Phase 2: Native/Framework bypass (Frida) ---
        try {
            FridaController frida = new FridaController(lpparam);
            frida.init();
        } catch (Throwable t) {
            XposedBridge.log("TrustMeAlready [" + packageName
                    + "] Frida init failed: " + t.getMessage());
        }

        XposedBridge.log("TrustMeAlready [" + packageName + "] v2.8 loaded!");
    }
}
