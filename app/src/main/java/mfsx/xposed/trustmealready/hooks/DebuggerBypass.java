package mfsx.xposed.trustmealready.hooks;

import android.os.Process;

import de.robv.android.xposed.XC_MethodHook;
import mfsx.xposed.trustmealready.HookHelper;

/**
 * Bypasses debugger detection and anti-tamper self-exit.
 *
 * <p>Hooks:
 * <ul>
 *   <li>Debug.isDebuggerConnected ? false</li>
 *   <li>Debug.waitForDebugger ? no-op</li>
 *   <li>Process.killProcess(self) ? blocked</li>
 *   <li>System.exit / Runtime.exit ? blocked (prevents anti-proxy self-exit)</li>
 * </ul>
 *
 * <p><b>SAFETY:</b> Does NOT hook BufferedReader.readLine globally.
 */
public class DebuggerBypass implements HookModule {

    @Override
    public String name() {
        return "Debugger Detection Bypass";
    }

    @Override
    public void apply(HookHelper h) {
        hookDebugApis(h);
        hookProcessKillProcess(h);
        hookSystemExit(h);
        hookRuntimeExit(h);
    }

    // ------------------------------------------------------------------
    // Debug.isDebuggerConnected ? false, waitForDebugger ? no-op
    // ------------------------------------------------------------------
    private void hookDebugApis(HookHelper h) {
        try {
            h.hookMethodsReturnConstant("android.os.Debug", false,
                    "isDebuggerConnected");
        } catch (Throwable t) {
            h.logError("Debug.isDebuggerConnected", t);
        }

        try {
            h.hookMethodsDoNothing("android.os.Debug",
                    "waitForDebugger");
        } catch (Throwable t) {
            h.logError("Debug.waitForDebugger", t);
        }
    }

    // ------------------------------------------------------------------
    // Process.killProcess - block self-kill (anti-debug prevention)
    // ------------------------------------------------------------------
    private void hookProcessKillProcess(HookHelper h) {
        try {
            h.hookMethodsWithCallback("android.os.Process",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                if (param.args != null && param.args.length > 0
                                        && param.args[0] instanceof Integer) {
                                    int targetPid = (Integer) param.args[0];
                                    int myPid = Process.myPid();
                                    if (targetPid == myPid) {
                                        param.setResult(null);
                                    }
                                }
                            } catch (Throwable ignored) {
                                // let original proceed on error
                            }
                        }
                    }, "killProcess");
        } catch (Throwable t) {
            h.logError("Process.killProcess", t);
        }
    }

    // ------------------------------------------------------------------
    // System.exit - block (prevents anti-proxy / anti-debug self-exit)
    // ------------------------------------------------------------------
    private void hookSystemExit(HookHelper h) {
        try {
            h.hookMethodsWithCallback("java.lang.System",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                XposedBridgeLog("System.exit(" + param.args[0] + ") blocked");
                                param.setResult(null);
                            } catch (Throwable ignored) {
                                // let original proceed on error
                            }
                        }
                    }, "exit");
        } catch (Throwable t) {
            h.logError("System.exit", t);
        }
    }

    // ------------------------------------------------------------------
    // Runtime.exit - block (prevents anti-proxy / anti-debug self-exit)
    // ------------------------------------------------------------------
    private void hookRuntimeExit(HookHelper h) {
        try {
            h.hookMethodsWithCallback("java.lang.Runtime",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                XposedBridgeLog("Runtime.exit(" + param.args[0] + ") blocked");
                                param.setResult(null);
                            } catch (Throwable ignored) {
                                // let original proceed on error
                            }
                        }
                    }, "exit");
        } catch (Throwable t) {
            h.logError("Runtime.exit", t);
        }
    }

    private void XposedBridgeLog(String msg) {
        de.robv.android.xposed.XposedBridge.log(
                "TrustMeAlready [Anti-Exit] " + msg);
    }
}
