package mfsx.xposed.trustmealready.hooks;

import mfsx.xposed.trustmealready.HookHelper;

/**
 * Bypasses user-added certificate detection by intercepting
 * TrustManagerImpl, TrustedCertificateStore, and NetworkSecurityConfig
 * methods that check whether a certificate is user-installed or a trust
 * anchor.
 */
public class UserCertificateBypass implements HookModule {

    @Override
    public String name() {
        return "User Certificate Detection Bypass";
    }

    @Override
    public void apply(HookHelper h) {
        hookTrustManagerImpl(h);
        hookTrustedCertificateStore(h);
        hookNetworkSecurityConfig(h);
    }

    // ------------------------------------------------------------------
    // TrustManagerImpl.isUserAddedCertificate ? false
    // ------------------------------------------------------------------
    private void hookTrustManagerImpl(HookHelper h) {
        try {
            h.hookMethodsReturnConstant(
                    "com.android.org.conscrypt.TrustManagerImpl", false,
                    "isUserAddedCertificate");
        } catch (Throwable t) {
            h.logError("TrustManagerImpl.isUserAddedCertificate", t);
        }

        // Legacy Harmony variant
        try {
            h.hookMethodsReturnConstant(
                    "org.apache.harmony.xnet.provider.jsse.TrustManagerImpl", false,
                    "isUserAddedCertificate");
        } catch (Throwable t) {
            h.logError("Legacy Harmony TrustManagerImpl.isUserAddedCertificate", t);
        }
    }

    // ------------------------------------------------------------------
    // TrustedCertificateStore - isUserAddedCertificate ? false,
    // isTrustAnchor ? true
    // ------------------------------------------------------------------
    private void hookTrustedCertificateStore(HookHelper h) {
        // isUserAddedCertificate ? false
        try {
            h.hookMethodsReturnConstant(
                    "com.android.org.conscrypt.TrustedCertificateStore", false,
                    "isUserAddedCertificate");
        } catch (Throwable t) {
            h.logError("TrustedCertificateStore.isUserAddedCertificate", t);
        }

        // isTrustAnchor ? true
        try {
            h.hookMethodsReturnConstant(
                    "com.android.org.conscrypt.TrustedCertificateStore", true,
                    "isTrustAnchor");
        } catch (Throwable t) {
            h.logError("TrustedCertificateStore.isTrustAnchor", t);
        }
    }

    // ------------------------------------------------------------------
    // NetworkSecurityConfig - user CA methods return true for booleans
    // ------------------------------------------------------------------
    private void hookNetworkSecurityConfig(HookHelper h) {
        // Boolean user CA methods ? return true
        try {
            h.hookMethodsReturnConstant(
                    "android.security.net.config.NetworkSecurityConfig", true,
                    "isUserAddedCertsTrusted", "hasPermittedDomains", "isCaInUserStore");
        } catch (Throwable t) {
            h.logError("NetworkSecurityConfig user CA boolean methods", t);
        }

        // ManifestConfigSource if present
        try {
            h.hookMethodsReturnConstant(
                    "android.security.net.config.ManifestConfigSource", true,
                    "isUserAddedCertsTrusted");
        } catch (Throwable t) {
            h.logError("ManifestConfigSource user CA methods", t);
        }
    }
}
