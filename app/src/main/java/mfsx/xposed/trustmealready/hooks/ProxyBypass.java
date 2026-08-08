package mfsx.xposed.trustmealready.hooks;

import java.net.Proxy;
import java.util.ArrayList;
import java.util.List;

import de.robv.android.xposed.XC_MethodHook;
import mfsx.xposed.trustmealready.HookHelper;

/**
 * Bypasses system proxy detection by intercepting System.getProperty
 * for proxy keys, ProxySelector.select, and ConnectivityManager.getDefaultProxy.
 */
public class ProxyBypass implements HookModule {

    @Override
    public String name() {
        return "Proxy Detection Bypass";
    }

    @Override
    public void apply(HookHelper h) {
        hookSystemGetProperty(h);
        hookProxySelectorSelect(h);
        hookConnectivityManagerGetDefaultProxy(h);
    }

    // ------------------------------------------------------------------
    // System.getProperty - return null for proxy-related keys
    // ------------------------------------------------------------------
    private void hookSystemGetProperty(HookHelper h) {
        try {
            h.hookMethodsWithCallback("java.lang.System",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                if (param.args != null && param.args.length > 0
                                        && param.args[0] instanceof String) {
                                    String key = (String) param.args[0];
                                    if (isProxyProperty(key)) {
                                        param.setResult(null);
                                    }
                                }
                            } catch (Throwable ignored) {
                                // let original proceed on error
                            }
                        }
                    }, "getProperty");
        } catch (Throwable t) {
            h.logError("System.getProperty", t);
        }
    }

    // ------------------------------------------------------------------
    // ProxySelector.select - return NO_PROXY list.
    // Hook CONCRETE implementations only; hooking the abstract method
    // on java.net.ProxySelector can crash ART on some Android versions.
    // ------------------------------------------------------------------
    private void hookProxySelectorSelect(HookHelper h) {
        XC_MethodHook proxyHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                try {
                    List<Proxy> noProxyList = new ArrayList<>();
                    noProxyList.add(Proxy.NO_PROXY);
                    param.setResult(noProxyList);
                } catch (Throwable ignored) {
                    // let original proceed on error
                }
            }
        };

        // Android's internal ProxySelector implementation
        try {
            h.hookMethodsWithCallback(
                    "com.android.okhttp.internalandroidapi.AndroidProxySelector",
                    proxyHook, "select");
        } catch (Throwable t) {
            h.logError("AndroidProxySelector.select", t);
        }

        // Java's default ProxySelector implementation
        try {
            h.hookMethodsWithCallback("sun.net.spi.DefaultProxySelector",
                    proxyHook, "select");
        } catch (Throwable t) {
            h.logError("DefaultProxySelector.select", t);
        }
    }

    // ------------------------------------------------------------------
    // ConnectivityManager.getDefaultProxy - return null
    // ------------------------------------------------------------------
    private void hookConnectivityManagerGetDefaultProxy(HookHelper h) {
        try {
            h.hookMethodsWithCallback("android.net.ConnectivityManager",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                param.setResult(null);
                            } catch (Throwable ignored) {
                                // let original proceed on error
                            }
                        }
                    }, "getDefaultProxy");
        } catch (Throwable t) {
            h.logError("ConnectivityManager.getDefaultProxy", t);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    private static boolean isProxyProperty(String key) {
        if (key == null) return false;
        return key.equals("http.proxyHost")
                || key.equals("http.proxyPort")
                || key.equals("https.proxyHost")
                || key.equals("https.proxyPort")
                || key.equals("ftp.proxyHost")
                || key.equals("ftp.proxyPort")
                || key.equals("socksProxyHost")
                || key.equals("socksProxyPort")
                || key.equals("proxyHost")
                || key.equals("proxyPort");
    }
}
