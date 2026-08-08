package mfsx.xposed.trustmealready.hooks;

import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import de.robv.android.xposed.XC_MethodHook;
import mfsx.xposed.trustmealready.HookHelper;

/**
 * Bypasses common VPN detection techniques including NetworkCapabilities
        * transport checks, NetworkInterface enumeration, and shell command
        * probes that inspect routing tables.
 */
public class VPNBypass implements HookModule {

    private static final int TRANSPORT_VPN = 4;

    @Override
    public String name() {
        return "VPN Detection Bypass";
    }

    @Override
    public void apply(HookHelper h) {
        hookNetworkCapabilitiesHasTransport(h);
        hookNetworkInterfaceEnumeration(h);
        hookNetworkInterfaceProperties(h);
        hookRuntimeExec(h);
    }

    // ------------------------------------------------------------------
    // NetworkCapabilities.hasTransport - hide VPN transport
    // ------------------------------------------------------------------
    private void hookNetworkCapabilitiesHasTransport(HookHelper h) {
        try {
            h.hookMethodsWithCallback("android.net.NetworkCapabilities",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                if (param.args != null && param.args.length > 0
                                        && param.args[0] instanceof Integer) {
                                    int transport = (Integer) param.args[0];
                                    if (transport == TRANSPORT_VPN) {
                                        param.setResult(false);
                                    }
                                }
                            } catch (Throwable ignored) {
                                // let original proceed on error
                            }
                        }
                    }, "hasTransport");
        } catch (Throwable t) {
            h.logError("NetworkCapabilities.hasTransport", t);
        }
    }

    // ------------------------------------------------------------------
    // NetworkInterface.getNetworkInterfaces - filter VPN interfaces
    // ------------------------------------------------------------------
    private void hookNetworkInterfaceEnumeration(HookHelper h) {
        try {
            h.hookMethodsWithCallback("java.net.NetworkInterface",
                    new XC_MethodHook() {
                        @Override
                        @SuppressWarnings("unchecked")
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Object result = param.getResult();
                                if (result == null) return;
                                Enumeration<NetworkInterface> original =
                                        (Enumeration<NetworkInterface>) result;
                                List<NetworkInterface> filtered = new ArrayList<>();
                                while (original.hasMoreElements()) {
                                    NetworkInterface ni = original.nextElement();
                                    if (ni != null && !isVpnInterface(ni.getName())) {
                                        filtered.add(ni);
                                    }
                                }
                                param.setResult(Collections.enumeration(filtered));
                            } catch (Throwable ignored) {
                                // keep original result on failure
                            }
                        }
                    }, "getNetworkInterfaces", "getNetworkInterfacesImpl");
        } catch (Throwable t) {
            h.logError("NetworkInterface.getNetworkInterfaces", t);
        }
    }

    // ------------------------------------------------------------------
    // NetworkInterface.isUp / isVirtual - return false for VPN interfaces
    // ------------------------------------------------------------------
    private void hookNetworkInterfaceProperties(HookHelper h) {
        try {
            h.hookMethodsWithCallback("java.net.NetworkInterface",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                String name = ((NetworkInterface) param.thisObject).getName();
                                if (isVpnInterface(name)) {
                                    param.setResult(false);
                                }
                            } catch (Throwable ignored) {
                                // let original proceed
                            }
                        }
                    }, "isUp", "isVirtual");
        } catch (Throwable t) {
            h.logError("NetworkInterface.isUp/isVirtual", t);
        }
    }

    // ------------------------------------------------------------------
    // Runtime.exec - neutralise route inspection commands
    // ------------------------------------------------------------------
    private void hookRuntimeExec(HookHelper h) {
        try {
            h.hookMethodsWithCallback("java.lang.Runtime",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                if (param.args == null || param.args.length == 0) return;
                                if (param.args[0] instanceof String) {
                                    String cmd = (String) param.args[0];
                                    if (isRouteInspectionCommand(cmd)) {
                                        param.args[0] = "echo";
                                    }
                                } else if (param.args[0] instanceof String[]) {
                                    String[] cmdArray = (String[]) param.args[0];
                                    if (cmdArray.length > 0
                                            && isRouteInspectionCommand(cmdArray[0])) {
                                        param.args[0] = new String[]{"echo"};
                                    }
                                }
                            } catch (Throwable ignored) {
                                // let original proceed on error
                            }
                        }
                    }, "exec");
        } catch (Throwable t) {
            h.logError("Runtime.exec", t);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    private static boolean isVpnInterface(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase();
        return lower.startsWith("tun")
                || lower.startsWith("tap")
                || lower.startsWith("ppp")
                || lower.startsWith("vpn");
    }

    private static boolean isRouteInspectionCommand(String cmd) {
        if (cmd == null) return false;
        String lower = cmd.toLowerCase();
        return lower.contains("ip route")
                || lower.contains("netstat")
                || lower.contains("ifconfig");
    }
}
