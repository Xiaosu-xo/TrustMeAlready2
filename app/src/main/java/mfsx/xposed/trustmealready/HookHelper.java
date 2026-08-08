package mfsx.xposed.trustmealready;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import static de.robv.android.xposed.XC_MethodReplacement.DO_NOTHING;
import static de.robv.android.xposed.XC_MethodReplacement.returnConstant;

/**
 * Centralised helper that reduces boilerplate across all hook modules.
 * Every method swallows Throwable so one module's failure never blocks another.
 *
 * <p><b>Key design:</b> try-catch is placed INSIDE the method-iteration
 * loop so that a single failed hook (e.g. abstract, final, or incompatible
 * signature) does NOT prevent remaining overloaded methods from being
 * hooked.
 */
public final class HookHelper {

    public final LoadPackageParam lpparam;
    public final ClassLoader classLoader;
    public final String packageName;

    public int hookedMethods = 0;
    public int errors = 0;

    public HookHelper(LoadPackageParam lpparam) {
        this.lpparam = lpparam;
        this.classLoader = lpparam.classLoader;
        this.packageName = lpparam.packageName;
    }

    public Class<?> findClass(String className) {
        try {
            return XposedHelpers.findClass(className, classLoader);
        } catch (Throwable t) {
            return null;
        }
    }

    public boolean classExists(String className) {
        return findClass(className) != null;
    }

    /**
     * Hook all declared methods matching any of the given names with a
     * MethodReplacement. Each method is hooked independently - a failure
     * on one method does not block the others.
     */
    public void hookMethodsByName(String className, XC_MethodReplacement replacement, String... methodNames) {
        Class<?> clazz = findClass(className);
        if (clazz == null) return;
        for (Method method : clazz.getDeclaredMethods()) {
            for (String name : methodNames) {
                if (method.getName().equals(name)) {
                    try {
                        List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                        params.add(replacement);
                        XposedHelpers.findAndHookMethod(clazz, name, params.toArray());
                        logHook(method.toString());
                    } catch (Throwable t) {
                        logError(method.toString(), t);
                    }
                    break;
                }
            }
        }
    }

    /**
     * Hook all declared methods matching any of the given names with a
     * MethodHook callback. Each method is hooked independently.
     */
    public void hookMethodsWithCallback(String className, XC_MethodHook hook, String... methodNames) {
        Class<?> clazz = findClass(className);
        if (clazz == null) return;
        for (Method method : clazz.getDeclaredMethods()) {
            for (String name : methodNames) {
                if (method.getName().equals(name)) {
                    try {
                        List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                        params.add(hook);
                        XposedHelpers.findAndHookMethod(clazz, name, params.toArray());
                        logHook(method.toString());
                    } catch (Throwable t) {
                        logError(method.toString(), t);
                    }
                    break;
                }
            }
        }
    }

    /**
     * Hook all declared methods matching any of the given names to return
     * a constant value. Void methods are hooked with DO_NOTHING instead.
     * Each method is hooked independently.
     */
    public void hookMethodsReturnConstant(String className, Object constant, String... methodNames) {
        Class<?> clazz = findClass(className);
        if (clazz == null) return;
        for (Method method : clazz.getDeclaredMethods()) {
            for (String name : methodNames) {
                if (method.getName().equals(name)) {
                    try {
                        List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                        if (method.getReturnType().equals(void.class)) {
                            params.add(DO_NOTHING);
                        } else {
                            params.add(returnConstant(constant));
                        }
                        XposedHelpers.findAndHookMethod(clazz, name, params.toArray());
                        logHook(method.toString());
                    } catch (Throwable t) {
                        logError(method.toString(), t);
                    }
                    break;
                }
            }
        }
    }

    public void hookMethodsDoNothing(String className, String... methodNames) {
        hookMethodsByName(className, DO_NOTHING, methodNames);
    }

    public void hookMethod(String className, String methodName, XC_MethodHook hook, Object... paramTypes) {
        try {
            XposedHelpers.findAndHookMethod(className, classLoader, methodName, appendParam(paramTypes, hook));
            logHook(className + "." + methodName);
        } catch (Throwable t) {
            logError(className + "." + methodName, t);
        }
    }

    public void hookConstructor(String className, XC_MethodHook hook, Object... paramTypes) {
        try {
            Class<?> clazz = findClass(className);
            if (clazz == null) return;
            XposedHelpers.findAndHookConstructor(clazz, appendParam(paramTypes, hook));
            logHook(className + ".<init>");
        } catch (Throwable t) {
            logError(className + ".<init>", t);
        }
    }

    public void log(String msg) {
        XposedBridge.log("TrustMeAlready [" + packageName + "] " + msg);
    }

    public void logHook(String method) {
        XposedBridge.log("TrustMeAlready [" + packageName + "] Hooked: " + method);
        hookedMethods++;
    }

    public void logError(String target, Throwable t) {
        XposedBridge.log("TrustMeAlready [" + packageName + "] Error hooking " + target + ": " + t.getMessage());
        errors++;
    }

    private static Object[] appendParam(Object[] paramTypes, XC_MethodHook hook) {
        Object[] result = new Object[paramTypes.length + 1];
        System.arraycopy(paramTypes, 0, result, 0, paramTypes.length);
        result[paramTypes.length] = hook;
        return result;
    }

    public static int getApiLevel() {
        return android.os.Build.VERSION.SDK_INT;
    }

    public static boolean apiAtLeast(int level) {
        return android.os.Build.VERSION.SDK_INT >= level;
    }
}
