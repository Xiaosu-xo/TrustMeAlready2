package mfsx.xposed.trustmealready.hooks;

import mfsx.xposed.trustmealready.HookHelper;

/**
 * Interface implemented by every hook module.
 * Modules are self-contained: each apply() call registers its hooks
 * and must never throw.
 */
public interface HookModule {
    String name();
    void apply(HookHelper helper);
}
