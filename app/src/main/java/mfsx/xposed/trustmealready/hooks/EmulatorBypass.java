package mfsx.xposed.trustmealready.hooks;

import de.robv.android.xposed.XC_MethodHook;
import mfsx.xposed.trustmealready.HookHelper;

/**
 * Bypasses emulator detection by masking the most reliable emulator signal
 * (ro.kernel.qemu) via SystemProperties.
 *
 * <p><b>SAFETY:</b> Does NOT modify any Build fields (MODEL, BRAND,
 * MANUFACTURER, FINGERPRINT, etc.). Changing device-identifiable fields
 * causes account auto-logout and can crash apps that load device-specific
 * resources or validate fingerprint format.
 * Does NOT modify SDK_INT, RELEASE, or CPU_ABI.
 * Does NOT hook File.exists or Runtime.exec globally.
 */
public class EmulatorBypass implements HookModule {

    @Override
    public String name() {
        return "Emulator Detection Bypass";
    }

    @Override
    public void apply(HookHelper h) {
        // SystemProperties.get() hook REMOVED - was hooking ALL overloads of
        // get() (thousands of calls/sec during app startup), and was DUPLICATED
        // by DeveloperOptionsBypass which also hooks SystemProperties.get().
        // The ro.kernel.qemu check has been merged into DeveloperOptionsBypass.
        // This eliminates the double-hook performance bottleneck.
        //
        // To re-add emulator-specific hooks in the future, use targeted hooks
        // on specific methods (NOT global hooks on high-frequency methods like
        // SystemProperties.get(), File.exists, or BufferedReader.readLine).
    }

    // ------------------------------------------------------------------
    // SystemProperties.get - only mask ro.kernel.qemu (emulator signal)
    // ------------------------------------------------------------------
    private void hookSystemPropertiesGet(HookHelper h) {
        try {
            h.hookMethodsWithCallback("android.os.SystemProperties",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                if (param.args != null && param.args.length > 0
                                        && param.args[0] instanceof String) {
                                    String key = (String) param.args[0];
                                    // Only intercept the single most reliable emulator signal
                                    if ("ro.kernel.qemu".equals(key)) {
                                        param.setResult("");
                                    }
                                }
                            } catch (Throwable ignored) {
                                // let original proceed on error
                            }
                        }
                    }, "get");
        } catch (Throwable t) {
            h.logError("SystemProperties.get (emulator)", t);
        }
    }
}
