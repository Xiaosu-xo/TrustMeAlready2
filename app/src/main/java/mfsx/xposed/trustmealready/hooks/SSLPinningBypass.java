package mfsx.xposed.trustmealready.hooks;

import static de.robv.android.xposed.XposedHelpers.callMethod;
import static de.robv.android.xposed.XposedHelpers.callStaticMethod;
import static de.robv.android.xposed.XposedHelpers.getObjectField;
import static de.robv.android.xposed.XposedHelpers.newInstance;
import static de.robv.android.xposed.XposedHelpers.setObjectField;

import android.annotation.SuppressLint;

import org.apache.http.conn.scheme.HostNameResolver;
import org.apache.http.conn.ssl.SSLSocketFactory;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import mfsx.xposed.trustmealready.DummyHostnameVerifier;
import mfsx.xposed.trustmealready.DummySSLSocketFactory;
import mfsx.xposed.trustmealready.DummyTrustManager;
import mfsx.xposed.trustmealready.HookHelper;

/**
 * Refactored SSL pinning bypass covering the full set of trust-verification
 * targets from the original Main.java plus additional framework and
 * third-party pinning implementations.
 */
public class SSLPinningBypass implements HookModule {

    @Override
    public String name() {
        return "SSL Pinning Bypass";
    }

    @Override
    public void apply(HookHelper h) {
        hookConscryptTrustManagerImpl(h);
        hookLegacyHarmonyTrustManagerImpl(h);
        // hookOpenSSLSocketImpls REMOVED - verifyCertificateChain is responsible
        // for calling TrustManager.checkServerTrusted() AND setting the SSL
        // session's peer certificate chain. Hooking it to no-op left the session
        // with no peer certificates, which broke apps (especially WeChat mini
        // program image loading) that read peer certs for pinning/CT/OCSP.
        // The TrustManager hooks (checkServerTrusted, verifyChain) are sufficient
        // for SSL pinning bypass.
        // hookOpenSSLSocketImpls(h);
        hookCertPinManagers(h);
        hookNetworkSecurityTrustManager(h);
        hookWebViewClient(h);
        hookHttpsURLConnection(h);
        hookSSLContext(h);
        hookSSLContextGetInstance(h);
        hookTLSProtocolEnforcement(h);
        hookTrustManagerFactory(h);
        hookApacheHttpClient(h);
        hookOkHttpCertificatePinner(h);
        hookOkHostnameVerifiers(h);
        hookXUtils(h);
        hookCertificateTransparency(h);
        hookTrustKit(h);
        hookWorkLight(h);
        hookCordova(h);
        hookCronet(h);
        hookNetty(h);
        hookAbstractVerifier(h);
        hookAppcelerator(h);
        hookTurkcellPaycell(h);
        hookSslCertificateChecker(h);
        hookCommonsWareCertPinManager(h);
    }

    // ------------------------------------------------------------------
    // Conscrypt TrustManagerImpl
    // ------------------------------------------------------------------
    private void hookConscryptTrustManagerImpl(HookHelper h) {
        try {
            final String className = "com.android.org.conscrypt.TrustManagerImpl";
            // Return the ORIGINAL certificate chain (not empty list) so that
            // downstream code - SSL session peer certificates, OkHttp pinning,
            // Conscrypt CT checks, OCSP - has the certificate info it needs.
            // Returning an empty ArrayList broke WeChat mini program image
            // loading because the SSL session had no peer certificate chain.
            h.hookMethodsWithCallback(className, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.args == null || param.args.length == 0) return;
                        Object arg0 = param.args[0];
                        if (arg0 instanceof X509Certificate[]) {
                            X509Certificate[] chain = (X509Certificate[]) arg0;
                            List<X509Certificate> list = new ArrayList<>();
                            for (X509Certificate cert : chain) {
                                if (cert != null) list.add(cert);
                            }
                            param.setResult(list);
                        } else if (arg0 instanceof List) {
                            param.setResult(new ArrayList<>((List<?>) arg0));
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }, "checkTrustedRecursive", "checkServerTrusted", "checkTrusted");
            h.hookMethodsWithCallback(className, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.args != null && param.args.length > 0) {
                            param.setResult(param.args[0]);
                        }
                    } catch (Throwable ignored) {
                        // let original proceed on error
                    }
                }
            }, "verifyChain");
        } catch (Throwable t) {
            h.logError("Conscrypt TrustManagerImpl", t);
        }
    }

    // ------------------------------------------------------------------
    // Legacy Harmony TrustManagerImpl
    // ------------------------------------------------------------------
    private void hookLegacyHarmonyTrustManagerImpl(HookHelper h) {
        try {
            final String className = "org.apache.harmony.xnet.provider.jsse.TrustManagerImpl";
            // Same fix as Conscrypt: return original chain, not empty list.
            h.hookMethodsWithCallback(className, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.args == null || param.args.length == 0) return;
                        Object arg0 = param.args[0];
                        if (arg0 instanceof X509Certificate[]) {
                            X509Certificate[] chain = (X509Certificate[]) arg0;
                            List<X509Certificate> list = new ArrayList<>();
                            for (X509Certificate cert : chain) {
                                if (cert != null) list.add(cert);
                            }
                            param.setResult(list);
                        } else if (arg0 instanceof List) {
                            param.setResult(new ArrayList<>((List<?>) arg0));
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }, "checkTrustedRecursive", "checkServerTrusted", "checkTrusted");
            h.hookMethodsWithCallback(className, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.args != null && param.args.length > 0) {
                            param.setResult(param.args[0]);
                        }
                    } catch (Throwable ignored) {
                        // let original proceed on error
                    }
                }
            }, "verifyChain");
        } catch (Throwable t) {
            h.logError("Legacy Harmony TrustManagerImpl", t);
        }
    }

    // ------------------------------------------------------------------
    // OpenSSLSocketImpl, OpenSSLEngineSocketImpl, ConscryptFileDescriptorSocket
    // ------------------------------------------------------------------
    private void hookOpenSSLSocketImpls(HookHelper h) {
        h.hookMethodsDoNothing("com.android.org.conscrypt.OpenSSLSocketImpl",
                "verifyCertificateChain");
        h.hookMethodsDoNothing("com.android.org.conscrypt.OpenSSLEngineSocketImpl",
                "verifyCertificateChain");
        h.hookMethodsDoNothing("com.android.org.conscrypt.ConscryptFileDescriptorSocket",
                "verifyCertificateChain");
        h.hookMethodsDoNothing("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl",
                "verifyCertificateChain");
    }

    // ------------------------------------------------------------------
    // CertPinManager (Conscrypt + CommonsWare)
    // ------------------------------------------------------------------
    private void hookCertPinManagers(HookHelper h) {
        h.hookMethodsReturnConstant(
                "com.android.org.conscrypt.CertPinManager", true, "isChainValid");
        h.hookMethodsReturnConstant(
                "com.commonsware.cwac.netsecurity.conscrypt.CertPinManager", true, "isChainValid");
    }

    // ------------------------------------------------------------------
    // NetworkSecurityTrustManager
    // ------------------------------------------------------------------
    private void hookNetworkSecurityTrustManager(HookHelper h) {
        h.hookMethodsDoNothing(
                "android.security.net.config.NetworkSecurityTrustManager", "checkPins");
    }

    // ------------------------------------------------------------------
    // WebViewClient + SslErrorHandler
    // ------------------------------------------------------------------
    private void hookWebViewClient(HookHelper h) {
        // 1) Hook onReceivedSslError on the base WebViewClient class.
        //    This catches apps that don't override onReceivedSslError.
        //    Uses XC_MethodHook (before) + setResult(null) instead of
        //    XC_MethodReplacement so that Xposed tracks it as a hook,
        //    not a replacement - this avoids interfering with WeChat's
        //    internal WebViewClient subclass dispatch.
        try {
            final String className = "android.webkit.WebViewClient";
            XposedBridge.hookAllMethods(
                    XposedHelpers.findClass(className, h.classLoader),
                    "onReceivedSslError", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                if (param.args != null && param.args.length > 1
                                        && param.args[1] instanceof android.webkit.SslErrorHandler) {
                                    ((android.webkit.SslErrorHandler) param.args[1]).proceed();
                                }
                            } catch (Throwable ignored) {
                            }
                            param.setResult(null);
                        }
                    });
            h.logHook("WebViewClient.onReceivedSslError");
        } catch (Throwable t) {
            h.logError("WebViewClient", t);
        }

        // 2) Hook onReceivedSslError on ALL loaded WebViewClient subclasses.
        //    Some apps (WeChat, Alipay, etc.) use a custom WebViewClient that
        //    overrides onReceivedSslError.  The hook on the base class doesn't
        //    catch the override.  We use XposedBridge.hookAllMethods on every
        //    class that declares onReceivedSslError.
        //
        //    IMPORTANT: We do NOT hook SslErrorHandler.cancel() globally.
        //    Apps like WeChat use cancel() internally for navigation cleanup
        //    (aborting old SSL connections before redirecting to external
        //    browser).  Redirecting cancel()?proceed() broke WeChat's
        //    in-app WebView, causing all links to jump to external browser.
        //    The onReceivedSslError hook above is sufficient - it calls
        //    proceed() before the app's code runs, so cancel() is never
        //    reached for SSL errors.
        try {
            hookOnReceivedSslErrorGlobally(h);
        } catch (Throwable t) {
            h.logError("onReceivedSslError global hook", t);
        }
    }

    // ------------------------------------------------------------------
    // Globally hook onReceivedSslError on any class that declares it.
    // Uses XposedBridge.hookAllMethods to catch ALL overrides, not just
    // the base WebViewClient.onReceivedSslError.
    // ------------------------------------------------------------------
    private void hookOnReceivedSslErrorGlobally(HookHelper h) {
        // Use XC_MethodHook (before) + setResult(null) instead of
        // XC_MethodReplacement.  Functionally equivalent (original method
        // is skipped) but avoids potential issues with Xposed's method
        // replacement tracking on subclasses with complex dispatch.
        XC_MethodHook autoProceed = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                try {
                    if (param.args != null && param.args.length > 1) {
                        Object handler = param.args[1];
                        if (handler instanceof android.webkit.SslErrorHandler) {
                            ((android.webkit.SslErrorHandler) handler).proceed();
                        } else {
                            XposedHelpers.callMethod(handler, "proceed");
                        }
                    }
                } catch (Throwable ignored) {
                }
                param.setResult(null);
            }
        };

        // Hook on common WebViewClient subclasses used by WeChat and other apps.
        // Base WebViewClient is already hooked in hookWebViewClient() above.
        // Only list actual WebViewClient subclasses here (not SslErrorHandler
        // or AwContents which don't declare onReceivedSslError).
        String[] knownSubclasses = {
                "com.tencent.xweb.WebViewClient",
                "com.tencent.smt.sdk.WebViewClient",
                "org.chromium.android_webview.AwWebViewClient",
                "com.uc.webengine.export.WebViewClient",
        };
        for (String clsName : knownSubclasses) {
            try {
                Class<?> cls = XposedHelpers.findClass(clsName, h.classLoader);
                if (cls != null) {
                    Set<?> hooks = XposedBridge.hookAllMethods(cls, "onReceivedSslError", autoProceed);
                    int count = hooks.size();
                    if (count > 0) {
                        h.logHook(clsName + ".onReceivedSslError (" + count + " methods)");
                    }
                }
            } catch (Throwable ignored) {
                // Class not loaded - skip
            }
        }
    }

    // ------------------------------------------------------------------
    // HttpsURLConnection (javax.net.ssl)
    // Replace hostname verifier argument with permissive DummyHostnameVerifier.
    // Do NOT block setSSLSocketFactory - apps like WeChat need to set their
    // own SSLSocketFactory for internal connections (mini program resources,
    // CDN, messaging). Blocking it breaks image loading and other resources.
    // The TrustManager replacement in SSLContext.init + Conscrypt hooks are
    // sufficient for certificate pinning bypass.
    // ------------------------------------------------------------------
    private void hookHttpsURLConnection(HookHelper h) {
        XC_MethodHook replaceVerifier = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                try {
                    if (param.args != null && param.args.length > 0) {
                        param.args[0] = new DummyHostnameVerifier();
                    }
                } catch (Throwable ignored) {
                }
            }
        };
        try {
            h.hookMethodsWithCallback("javax.net.ssl.HttpsURLConnection",
                    replaceVerifier, "setHostnameVerifier", "setDefaultHostnameVerifier");
            h.logHook("HttpsURLConnection.setHostnameVerifier (replace, not block)");
        } catch (Throwable t) {
            h.logError("HttpsURLConnection.setHostnameVerifier", t);
        }
    }

    // ------------------------------------------------------------------
    // SSLContext.init - replace ONLY TrustManager[] with DummyTrustManager.
    // Keep original KeyManager[] and SecureRandom to avoid breaking
    // mutual-TLS apps and custom SecureRandom providers.
    // ------------------------------------------------------------------
    private void hookSSLContext(HookHelper h) {
        try {
            h.hookMethodsWithCallback("javax.net.ssl.SSLContext", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        // Only replace TrustManager[] (arg index 1)
                        if (param.args != null && param.args.length >= 2) {
                            param.args[1] = DummyTrustManager.getInstance();
                        }
                    } catch (Throwable ignored) {
                        // let original proceed on error
                    }
                }
            }, "init");
        } catch (Throwable t) {
            h.logError("SSLContext.init", t);
        }
    }

    // ------------------------------------------------------------------
    // TrustManagerFactory.getTrustManagers - replace with DummyTrustManager
    // ------------------------------------------------------------------
    private void hookTrustManagerFactory(HookHelper h) {
        try {
            final String tmClassName = "com.android.org.conscrypt.TrustManagerImpl";
            h.hookMethodsWithCallback("javax.net.ssl.TrustManagerFactory", new XC_MethodHook() {
                @SuppressLint("PrivateApi")
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        Class<?> clazz = h.findClass(tmClassName);
                        if (clazz == null) return;
                        TrustManager[] trustManagers = (TrustManager[]) param.getResult();
                        if (trustManagers != null && trustManagers.length > 0
                                && clazz.isInstance(trustManagers[0])) {
                            return;
                        }
                    } catch (Throwable ignored) {
                        return;
                    }
                    param.setResult(DummyTrustManager.getInstance());
                }
            }, "getTrustManagers");
        } catch (Throwable t) {
            h.logError("TrustManagerFactory.getTrustManagers", t);
        }
    }

    // ------------------------------------------------------------------
    // Apache HttpClient
    // ------------------------------------------------------------------
    private void hookApacheHttpClient(HookHelper h) {
        // SchemeRegistry.register - swap https scheme
        try {
            h.hookMethodsWithCallback("org.apache.http.conn.scheme.SchemeRegistry",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Object obj = param.args[0];
                            if ("https".equals(callMethod(obj, "getName"))) {
                                param.args[0] = newInstance(obj.getClass(), "https",
                                        SSLSocketFactory.getSocketFactory(), 443);
                            }
                        }
                    }, "register");
        } catch (Throwable t) {
            h.logError("SchemeRegistry.register", t);
        }

        // Apache HttpsURLConnection - force ALLOW_ALL_HOSTNAME_VERIFIER
        try {
            h.hookMethodsWithCallback("org.apache.http.conn.ssl.HttpsURLConnection",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.args[0] = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
                        }
                    }, "setDefaultHostnameVerifier", "setHostnameVerifier");
        } catch (Throwable t) {
            h.logError("Apache HttpsURLConnection", t);
        }

        // SSLSocketFactory.getSocketFactory - return permissive factory
        try {
            h.hookMethodsWithCallback("org.apache.http.conn.ssl.SSLSocketFactory",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(newInstance(SSLSocketFactory.class));
                        }
                    }, "getSocketFactory");
        } catch (Throwable t) {
            h.logError("SSLSocketFactory.getSocketFactory", t);
        }

        // SSLSocketFactory.isSecure - always true
        h.hookMethodsReturnConstant(
                "org.apache.http.conn.ssl.SSLSocketFactory", true, "isSecure");

        // SSLSocketFactory constructor - re-initialise with DummyTrustManager
        try {
            h.hookConstructor("org.apache.http.conn.ssl.SSLSocketFactory",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            String algorithm = (String) param.args[0];
                            KeyStore keystore = (KeyStore) param.args[1];
                            String keystorePassword = (String) param.args[2];
                            SecureRandom random = (SecureRandom) param.args[4];

                            KeyManager[] keymanagers = null;
                            if (keystore != null) {
                                keymanagers = (KeyManager[]) callStaticMethod(
                                        SSLSocketFactory.class, "createKeyManagers",
                                        keystore, keystorePassword);
                            }

                            TrustManager[] trustmanagers = DummyTrustManager.getInstance();

                            setObjectField(param.thisObject, "sslcontext",
                                    SSLContext.getInstance(algorithm));
                            callMethod(getObjectField(param.thisObject, "sslcontext"),
                                    "init", keymanagers, trustmanagers, random);
                            setObjectField(param.thisObject, "socketfactory",
                                    callMethod(getObjectField(param.thisObject, "sslcontext"),
                                            "getSocketFactory"));
                        }
                    }, String.class, KeyStore.class, String.class, KeyStore.class,
                    SecureRandom.class, HostNameResolver.class);
        } catch (Throwable t) {
            h.logError("SSLSocketFactory constructor", t);
        }
    }

    // ------------------------------------------------------------------
    // OkHttp 3/4+ CertificatePinner + repackaged + Commencis fork
    // ------------------------------------------------------------------
    private void hookOkHttpCertificatePinner(HookHelper h) {
        // okhttp3 (v3 and v4+)
        try {
            final String className = "okhttp3.CertificatePinner";
            h.hookMethodsWithCallback(className, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.args != null && param.args.length > 0) {
                            param.args[0] = "";
                        }
                    } catch (Throwable ignored) {
                        // let original proceed on error
                    }
                }
            }, "findMatchingPins");
            h.hookMethodsDoNothing(className, "check", "check$okhttp");
        } catch (Throwable t) {
            h.logError("okhttp3.CertificatePinner", t);
        }

        // okhttp3 repackaged
        try {
            final String className = "okhttp3.repackaged.CertificatePinner";
            h.hookMethodsWithCallback(className, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.args != null && param.args.length > 0) {
                            param.args[0] = "";
                        }
                    } catch (Throwable ignored) {
                        // let original proceed on error
                    }
                }
            }, "findMatchingPins");
            h.hookMethodsDoNothing(className, "check", "check$okhttp");
        } catch (Throwable t) {
            h.logError("okhttp3.repackaged.CertificatePinner", t);
        }

        // Commencis fork
        h.hookMethodsDoNothing("com.commencis.okhttp3.CertificatePinner",
                "check", "check$okhttp");

        // Squareup OkHttp (v1/v2)
        h.hookMethodsDoNothing("com.squareup.okhttp.CertificatePinner", "check");
    }

    // ------------------------------------------------------------------
    // OkHostnameVerifier (okhttp3 + squareup)
    // ------------------------------------------------------------------
    private void hookOkHostnameVerifiers(HookHelper h) {
        h.hookMethodsReturnConstant(
                "okhttp3.internal.tls.OkHostnameVerifier", true, "verify");
        h.hookMethodsReturnConstant(
                "com.squareup.okhttp.internal.tls.OkHostnameVerifier", true, "verify");
    }

    // ------------------------------------------------------------------
    // xUtils
    // ------------------------------------------------------------------
    private void hookXUtils(HookHelper h) {
        try {
            final String className = "org.xutils.http.RequestParams";
            h.hookMethodsWithCallback(className, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.args[0] = DummySSLSocketFactory.createDefault();
                }
            }, "setSslSocketFactory");
            h.hookMethodsWithCallback(className, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.args[0] = new DummyHostnameVerifier();
                }
            }, "setHostnameVerifier");
        } catch (Throwable t) {
            h.logError("xUtils RequestParams", t);
        }
    }

    // ------------------------------------------------------------------
    // CertificateTransparency (interceptor + TrustManager)
    // ------------------------------------------------------------------
    private void hookCertificateTransparency(HookHelper h) {
        try {
            h.hookMethodsByName(
                    "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor",
                    new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) {
                            Object chain = param.args[0];
                            Object request = callMethod(chain, "request");
                            return callMethod(chain, "proceed", request);
                        }
                    }, "intercept");
        } catch (Throwable t) {
            h.logError("CertificateTransparencyInterceptor", t);
        }

        try {
            h.hookMethodsReturnConstant(
                    "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager",
                    new ArrayList<X509Certificate>(), "checkServerTrusted");
        } catch (Throwable t) {
            h.logError("CertificateTransparencyTrustManager", t);
        }
    }

    // ------------------------------------------------------------------
    // TrustKit
    // ------------------------------------------------------------------
    private void hookTrustKit(HookHelper h) {
        h.hookMethodsReturnConstant(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", true, "verify");
        h.hookMethodsDoNothing(
                "com.datatheorem.android.trustkit.pinning.PinningTrustManager", "checkServerTrusted");
    }

    // ------------------------------------------------------------------
    // WorkLight
    // ------------------------------------------------------------------
    private void hookWorkLight(HookHelper h) {
        h.hookMethodsDoNothing(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning",
                "verify");
        h.hookMethodsDoNothing(
                "com.worklight.wlclient.api.WLClient", "pinTrustedCertificatePublicKey");
        h.hookMethodsReturnConstant(
                "com.worklight.androidgap.plugin.WLCertificatePinningPlugin", true, "execute");
    }

    // ------------------------------------------------------------------
    // Cordova
    // ------------------------------------------------------------------
    private void hookCordova(HookHelper h) {
        try {
            h.hookMethodsByName("org.apache.cordova.CordovaWebViewClient",
                    new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) {
                            try {
                                if (param.args != null && param.args.length > 2
                                        && param.args[2] instanceof android.webkit.SslErrorHandler) {
                                    ((android.webkit.SslErrorHandler) param.args[2]).proceed();
                                }
                            } catch (Throwable ignored) {
                                // ignore
                            }
                            return null;
                        }
                    }, "onReceivedSslError");
        } catch (Throwable t) {
            h.logError("CordovaWebViewClient", t);
        }
    }

    // ------------------------------------------------------------------
    // Cronet
    // ------------------------------------------------------------------
    private void hookCronet(HookHelper h) {
        try {
            final String className = "org.chromium.net.CronetEngine$Builder";
            h.hookMethodsWithCallback(className, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.args != null && param.args.length > 0) {
                            param.args[0] = true;
                        }
                    } catch (Throwable ignored) {
                        // let original proceed on error
                    }
                }
            }, "enablePublicKeyPinningBypassForLocalTrustAnchors");
            h.hookMethodsByName(className, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) {
                    return param.thisObject;
                }
            }, "addPublicKeyPins");
        } catch (Throwable t) {
            h.logError("CronetEngine$Builder", t);
        }
    }

    // ------------------------------------------------------------------
    // Netty FingerprintTrustManagerFactory
    // ------------------------------------------------------------------
    private void hookNetty(HookHelper h) {
        h.hookMethodsDoNothing(
                "io.netty.handler.ssl.util.FingerprintTrustManagerFactory", "checkTrusted");
    }

    // ------------------------------------------------------------------
    // httpclientandroidlib AbstractVerifier
    // ------------------------------------------------------------------
    private void hookAbstractVerifier(HookHelper h) {
        h.hookMethodsDoNothing(
                "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier", "verify");
    }

    // ------------------------------------------------------------------
    // Appcelerator PinningTrustManager
    // ------------------------------------------------------------------
    private void hookAppcelerator(HookHelper h) {
        h.hookMethodsDoNothing(
                "appcelerator.https.PinningTrustManager", "checkServerTrusted");
    }

    // ------------------------------------------------------------------
    // Turkcell Paycell DataModule
    // ------------------------------------------------------------------
    private void hookTurkcellPaycell(HookHelper h) {
        h.hookMethodsReturnConstant(
                "com.turkcell.paycell.data.DataModule", true, "checkCertificate");
    }

    // ------------------------------------------------------------------
    // sslCertificateChecker Cordova plugin
    // ------------------------------------------------------------------
    private void hookSslCertificateChecker(HookHelper h) {
        h.hookMethodsReturnConstant(
                "nl.xservices.plugins.sslCertificateChecker", true, "execute");
    }

    // ------------------------------------------------------------------
    // CommonsWare CertPinManager
    // ------------------------------------------------------------------
    private void hookCommonsWareCertPinManager(HookHelper h) {
        h.hookMethodsReturnConstant(
                "com.commonsware.cwac.netsecurity.conscrypt.CertPinManager", true, "isChainValid");
    }

    // ------------------------------------------------------------------
    // SSLContext.getInstance - redirect all protocol variants to "TLS"
    // so the context supports all TLS versions the system offers.
    // Without this, getInstance("TLSv1.3") returns a context that can
    // ONLY negotiate TLS 1.3, breaking compatibility with older servers.
    // "TLS" context negotiates the highest mutually supported version
    // (TLS 1.3 on Android 10+, TLS 1.2 on Android 5-9).
    // ------------------------------------------------------------------
    private void hookSSLContextGetInstance(HookHelper h) {
        XC_MethodHook redirect = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                try {
                    if (param.args != null && param.args.length > 0
                            && param.args[0] instanceof String) {
                        String requested = (String) param.args[0];
                        if (!"TLS".equals(requested) && !"Default".equals(requested)) {
                            param.args[0] = "TLS";
                        }
                    }
                } catch (Throwable ignored) {
                }
            }
        };
        // getInstance(String protocol)
        try {
            XposedHelpers.findAndHookMethod("javax.net.ssl.SSLContext", h.classLoader,
                    "getInstance", String.class, redirect);
            h.logHook("SSLContext.getInstance(String) -> TLS redirect");
        } catch (Throwable t) {
            h.logError("SSLContext.getInstance(String)", t);
        }
        // getInstance(String protocol, Provider provider)
        try {
            Class<?> providerClass = XposedHelpers.findClass(
                    "java.security.Provider", h.classLoader);
            XposedHelpers.findAndHookMethod("javax.net.ssl.SSLContext", h.classLoader,
                    "getInstance", String.class, providerClass, redirect);
            h.logHook("SSLContext.getInstance(String, Provider) -> TLS redirect");
        } catch (Throwable t) {
            h.logError("SSLContext.getInstance(String, Provider)", t);
        }
        // getInstance(String protocol, String provider)
        try {
            XposedHelpers.findAndHookMethod("javax.net.ssl.SSLContext", h.classLoader,
                    "getInstance", String.class, String.class, redirect);
            h.logHook("SSLContext.getInstance(String, String) -> TLS redirect");
        } catch (Throwable t) {
            h.logError("SSLContext.getInstance(String, String)", t);
        }
    }

    // ------------------------------------------------------------------
    // TLS Protocol Enforcement - force-enable ALL supported TLS versions
    // on SSLSocket and SSLEngine.
    //
    // Apps that call setEnabledProtocols(new String[]{"TLSv1.3"}) restrict
    // the socket to TLS 1.3 only, causing connection failures with servers
    // that only support TLS 1.0/1.1/1.2. This hook replaces the restricted
    // protocol array with getSupportedProtocols() to enable everything
    // the system supports:
    //   - Android 5-9:  TLSv1, TLSv1.1, TLSv1.2
    //   - Android 10+:   TLSv1, TLSv1.1, TLSv1.2, TLSv1.3
    // ------------------------------------------------------------------
    private void hookTLSProtocolEnforcement(HookHelper h) {
        // SSLSocket.setEnabledProtocols ? replace with all supported
        try {
            Class<?> sslSocketClass = XposedHelpers.findClass(
                    "javax.net.ssl.SSLSocket", h.classLoader);
            XposedBridge.hookAllMethods(sslSocketClass, "setEnabledProtocols",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                String[] supported = (String[]) callMethod(
                                        param.thisObject, "getSupportedProtocols");
                                if (supported != null && supported.length > 0) {
                                    param.args[0] = supported;
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    });
            h.logHook("SSLSocket.setEnabledProtocols (force all TLS)");
        } catch (Throwable t) {
            h.logError("SSLSocket.setEnabledProtocols", t);
        }

        // SSLEngine.setEnabledProtocols ? replace with all supported
        try {
            Class<?> sslEngineClass = XposedHelpers.findClass(
                    "javax.net.ssl.SSLEngine", h.classLoader);
            XposedBridge.hookAllMethods(sslEngineClass, "setEnabledProtocols",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                String[] supported = (String[]) callMethod(
                                        param.thisObject, "getSupportedProtocols");
                                if (supported != null && supported.length > 0) {
                                    param.args[0] = supported;
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    });
            h.logHook("SSLEngine.setEnabledProtocols (force all TLS)");
        } catch (Throwable t) {
            h.logError("SSLEngine.setEnabledProtocols", t);
        }

        // SSLSocket.setSSLParameters ? after app sets restricted params,
        // re-enable all protocols. Some apps construct SSLParameters
        // directly instead of calling setEnabledProtocols.
        try {
            Class<?> sslSocketClass = XposedHelpers.findClass(
                    "javax.net.ssl.SSLSocket", h.classLoader);
            Class<?> sslParamsClass = XposedHelpers.findClass(
                    "javax.net.ssl.SSLParameters", h.classLoader);
            XposedBridge.hookAllMethods(sslSocketClass, "setSSLParameters",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                String[] supported = (String[]) callMethod(
                                        param.thisObject, "getSupportedProtocols");
                                if (supported != null && supported.length > 0) {
                                    callMethod(param.thisObject,
                                            "setEnabledProtocols", (Object) supported);
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    });
            h.logHook("SSLSocket.setSSLParameters (post-enforce all TLS)");
        } catch (Throwable t) {
            h.logError("SSLSocket.setSSLParameters", t);
        }

        // SSLEngine.setSSLParameters ? same as above for SSLEngine
        try {
            Class<?> sslEngineClass = XposedHelpers.findClass(
                    "javax.net.ssl.SSLEngine", h.classLoader);
            XposedBridge.hookAllMethods(sslEngineClass, "setSSLParameters",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                String[] supported = (String[]) callMethod(
                                        param.thisObject, "getSupportedProtocols");
                                if (supported != null && supported.length > 0) {
                                    callMethod(param.thisObject,
                                            "setEnabledProtocols", (Object) supported);
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    });
            h.logHook("SSLEngine.setSSLParameters (post-enforce all TLS)");
        } catch (Throwable t) {
            h.logError("SSLEngine.setSSLParameters", t);
        }
    }
}
