package mfsx.xposed.trustmealready.hooks;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;

import de.robv.android.xposed.XC_MethodHook;
import mfsx.xposed.trustmealready.HookHelper;

/**
 * Bypasses developer-options and ADB detection by intercepting
 * Settings lookups, SystemProperties reads, ActivityManager test-harness
 * checks, and clearing the FLAG_DEBUGGABLE bit from PackageInfo.
 */
public class DeveloperOptionsBypass implements HookModule {

    private static final int FLAG_DEBUGGABLE = 0x2;

    private static final String[] DEV_OPTION_KEYS = {
            "adb_enabled",
            "development_settings_enabled",
            "adb_wifi_enabled",
            "layout_bounds",
            "debug_layout",
            "show_screen_updates",
            "show_hw_screen_updates",
            "show_hw_overdraw",
            "show_hw_ui_layers",
            "show_non_rect_clip",
            "force_hw_ui",
            "force_msaa",
            "track_frame_time",
            "profile_display_maxres",
            "show_procesinfo",
            "enable_opengl_traces",
            "debug.app_proc_category",
            "debug.hwui.render_dirty_regions",
            "debug.hwui.show_dirty_regions",
            "wait_for_debugger",
            "debug.debuggable"
    };

    @Override
    public String name() {
        return "Developer Options Bypass";
    }

    @Override
    public void apply(HookHelper h) {
        hookSettingsGetInt(h);
        hookSettingsGetString(h);
        hookActivityManagerTestHarness(h);
        hookSystemPropertiesGet(h);
        hookPackageInfoFlags(h);
    }

    // ------------------------------------------------------------------
    // Settings.Secure / Settings.Global.getInt - return 0 for dev keys
    // ------------------------------------------------------------------
    private void hookSettingsGetInt(HookHelper h) {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                try {
                    if (param.args != null && param.args.length >= 2
                            && param.args[1] instanceof String) {
                        String key = (String) param.args[1];
                        if (isDevOptionKey(key)) {
                            param.setResult(0);
                        }
                    }
                } catch (Throwable ignored) {
                    // let original proceed on error
                }
            }
        };

        try {
            h.hookMethodsWithCallback("android.provider.Settings$Secure", hook,
                    "getInt");
        } catch (Throwable t) {
            h.logError("Settings.Secure.getInt", t);
        }

        try {
            h.hookMethodsWithCallback("android.provider.Settings$Global", hook,
                    "getInt");
        } catch (Throwable t) {
            h.logError("Settings.Global.getInt", t);
        }
    }

    // ------------------------------------------------------------------
    // Settings.Secure / Settings.Global.getString - return "0" for dev keys
    // ------------------------------------------------------------------
    private void hookSettingsGetString(HookHelper h) {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                try {
                    if (param.args != null && param.args.length >= 2
                            && param.args[1] instanceof String) {
                        String key = (String) param.args[1];
                        if (isDevOptionKey(key)) {
                            param.setResult("0");
                        }
                    }
                } catch (Throwable ignored) {
                    // let original proceed on error
                }
            }
        };

        try {
            h.hookMethodsWithCallback("android.provider.Settings$Secure", hook,
                    "getString");
        } catch (Throwable t) {
            h.logError("Settings.Secure.getString", t);
        }

        try {
            h.hookMethodsWithCallback("android.provider.Settings$Global", hook,
                    "getString");
        } catch (Throwable t) {
            h.logError("Settings.Global.getString", t);
        }
    }

    // ------------------------------------------------------------------
    // ActivityManager.isRunningInTestHarness - return false
    // ------------------------------------------------------------------
    private void hookActivityManagerTestHarness(HookHelper h) {
        try {
            h.hookMethodsReturnConstant("android.app.ActivityManager", false,
                    "isRunningInTestHarness");
        } catch (Throwable t) {
            h.logError("ActivityManager.isRunningInTestHarness", t);
        }
    }

    // ------------------------------------------------------------------
    // SystemProperties.get - spoof debug-related properties
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
                                    String spoofed = getSpoofedProperty(key);
                                    if (spoofed != null) {
                                        param.setResult(spoofed);
                                    }
                                }
                            } catch (Throwable ignored) {
                                // let original proceed on error
                            }
                        }
                    }, "get");
        } catch (Throwable t) {
            h.logError("SystemProperties.get", t);
        }
    }

    // ------------------------------------------------------------------
    // ApplicationPackageManager.getPackageInfo - clear FLAG_DEBUGGABLE
    // ------------------------------------------------------------------
    private void hookPackageInfoFlags(HookHelper h) {
        try {
            h.hookMethodsWithCallback("android.app.ApplicationPackageManager",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Object result = param.getResult();
                                if (result instanceof PackageInfo) {
                                    PackageInfo pi = (PackageInfo) result;
                                    if (pi.applicationInfo != null) {
                                        pi.applicationInfo.flags &= ~FLAG_DEBUGGABLE;
                                    }
                                }
                            } catch (Throwable ignored) {
                                // leave result unmodified on failure
                            }
                        }
                    }, "getPackageInfo");
        } catch (Throwable t) {
            h.logError("ApplicationPackageManager.getPackageInfo", t);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    private static boolean isDevOptionKey(String key) {
        if (key == null) return false;
        for (String devKey : DEV_OPTION_KEYS) {
            if (devKey.equals(key)) return true;
        }
        return false;
    }

    private static String getSpoofedProperty(String key) {
        if (key == null) return null;
        switch (key) {
            case "ro.debuggable":
                return "0";
            case "ro.secure":
                return "1";
            case "ro.build.type":
                return "user";
            case "ro.kernel.qemu":
                // Emulator detection bypass - merged from EmulatorBypass to
                // avoid duplicate hooks on SystemProperties.get() (high-frequency
                // method called thousands of times during app startup).
                return "";
            default:
                return null;
        }
    }
}
