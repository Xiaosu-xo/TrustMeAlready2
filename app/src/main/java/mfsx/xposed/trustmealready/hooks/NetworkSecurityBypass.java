package mfsx.xposed.trustmealready.hooks;

import de.robv.android.xposed.XC_MethodHook;
import mfsx.xposed.trustmealready.HookHelper;

/**
 * Bypasses Android Network Security Config restrictions by forcing
 * isCleartextTrafficPermitted to return true across all relevant
 * policy classes (API 24+).
 */
public class NetworkSecurityBypass implements HookModule {

    @Override
    public String name() {
        return "Network Security Config Bypass";
    }

    @Override
    public void apply(HookHelper h) {
        hookNetworkSecurityConfig(h);
        hookNetworkSecurityPolicy(h);
        hookConfigNetworkSecurityPolicy(h);
    }

    // ------------------------------------------------------------------
    // NetworkSecurityConfig.isCleartextTrafficPermitted ? true
    // ------------------------------------------------------------------
    private void hookNetworkSecurityConfig(HookHelper h) {
        try {
            h.hookMethodsReturnConstant(
                    "android.security.net.config.NetworkSecurityConfig", true,
                    "isCleartextTrafficPermitted");
        } catch (Throwable t) {
            h.logError("NetworkSecurityConfig.isCleartextTrafficPermitted", t);
        }
    }

    // ------------------------------------------------------------------
    // NetworkSecurityPolicy.isCleartextTrafficPermitted ? true
    // (both no-arg and String-arg overloads)
    // ------------------------------------------------------------------
    private void hookNetworkSecurityPolicy(HookHelper h) {
        try {
            h.hookMethodsWithCallback("android.security.NetworkSecurityPolicy",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                param.setResult(true);
                            } catch (Throwable ignored) {
                                // let original proceed on error
                            }
                        }
                    }, "isCleartextTrafficPermitted");
        } catch (Throwable t) {
            h.logError("NetworkSecurityPolicy.isCleartextTrafficPermitted", t);
        }
    }

    // ------------------------------------------------------------------
    // ConfigNetworkSecurityPolicy.isCleartextTrafficPermitted ? true
    // ------------------------------------------------------------------
    private void hookConfigNetworkSecurityPolicy(HookHelper h) {
        XC_MethodHook policyHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                try {
                    param.setResult(true);
                } catch (Throwable ignored) {
                    // let original proceed on error
                }
            }
        };

        try {
            h.hookMethodsWithCallback(
                    "android.security.net.config.ConfigNetworkSecurityPolicy",
                    policyHook, "isCleartextTrafficPermitted");
        } catch (Throwable t) {
            h.logError("ConfigNetworkSecurityPolicy.isCleartextTrafficPermitted", t);
        }

        // Also hook ManifestConfigSource if it implements the policy
        try {
            h.hookMethodsWithCallback(
                    "android.security.net.config.ManifestConfigSource",
                    policyHook, "isCleartextTrafficPermitted");
        } catch (Throwable t) {
            h.logError("ManifestConfigSource.isCleartextTrafficPermitted", t);
        }
    }
}
