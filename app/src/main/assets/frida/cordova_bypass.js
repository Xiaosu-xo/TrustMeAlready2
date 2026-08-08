/*
 * cordova_bypass.js
 * ---------------------------------------------------------------------------
 * ??: Cordova / Ionic ?? SSL Pinning ???????
 *
 * ????:
 *   Cordova/Ionic ???????? WebView ??? Web ??, ??????
 *   ?? WebView (System WebView / Crosswalk) ??? HTTP ?????SSL
 *   ?????? WebView ? SSL ????, ?? Ionic Native HTTP ??
 *   (@ionic-native/http) ????? OkHttp / Apache HttpClient?
 *
 * ????:
 *   - Cordova WebViewClient SSL ???? (onReceivedSslError)
 *   - Cordova ???? (config.xml whitelist + Content-Security-Policy)
 *   - Cordova ??????:
 *       * cordova-plugin-advanced-http (Native HTTP)
 *       * cordova-plugin-certificates / SSLCertificateChecker
 *       * phonegap-plugin-push / ??? (WorkLight) ??
 *   - Ionic Native HTTP (@ionic-native/http)
 *   - WebViewClient (System + Crosswalk) ?? SSL ??
 *
 * ????:
 *   - Cordova 8.x ~ 12.x
 *   - Ionic 3 / 4 / 5 / 6 / 7
 *   - cordova-android 8.x ~ 12.x
 *
 * ????: frida -U -l cordova_bypass.js -f <package> --no-pause
 * ---------------------------------------------------------------------------
 */

'use strict';

var _keepAlive = {};

// ---------------------------------------------------------------------------
// ?? Java hook ??
// ---------------------------------------------------------------------------
function tryHookJava(label, className, hooker) {
    if (!Java.available) {
        console.log('[-] Java ???, ?? ' + label);
        return;
    }
    try {
        var clazz = Java.use(className);
        hooker(clazz);
        console.log('[*] Hook ??? (Java): ' + label + ' [' + className + ']');
    } catch (e) {
        console.log('[-] ' + label + ' ???? hook ??: ' + e.message);
    }
}

// ---------------------------------------------------------------------------
// Cordova WebViewClient SSL ??????
// ---------------------------------------------------------------------------
function hookCordovaWebViewClient() {
    console.log('\n--- [1] Cordova WebViewClient SSL ???? ---');

    // Cordova 8/9: org.apache.cordova.CordovaWebViewClient
    tryHookJava('CordovaWebViewClient.onReceivedSslError',
        'org.apache.cordova.CordovaWebViewClient', function (clazz) {
            clazz.onReceivedSslError.implementation = function (view, handler, error) {
                console.log('[+] CordovaWebViewClient.onReceivedSslError: proceed (?? SSL ??)');
                handler.proceed();
                return;
            };
        });

    // Cordova 10+: org.apache.cordova.engine.SystemWebChromeClient / SystemWebViewClient
    tryHookJava('SystemWebViewClient.onReceivedSslError',
        'org.apache.cordova.engine.SystemWebViewClient', function (clazz) {
            clazz.onReceivedSslError.implementation = function (view, handler, error) {
                console.log('[+] SystemWebViewClient.onReceivedSslError: proceed');
                handler.proceed();
                return;
            };
            // onReceivedError ???
            try {
                var errOverloads = clazz.onReceivedError.overloads;
                for (var i = 0; i < errOverloads.length; i++) {
                    errOverloads[i].implementation = function () {
                        console.log('[+] SystemWebViewClient.onReceivedError: ??');
                    };
                }
            } catch (e) {}
        });

    // Crosswalk (?? Cordova ??? XWalk ?????)
    tryHookJava('XWalkCordovaViewClient.onReceivedSslError',
        'org.apache.cordova.engine.XWalkCordovaViewClient', function (clazz) {
            clazz.onReceivedSslError.implementation = function (view, callback, error) {
                console.log('[+] XWalkCordovaViewClient.onReceivedSslError: proceed');
                callback.proceed();
                return;
            };
        });

    // ?? android.webkit.WebViewClient (??)
    tryHookJava('WebViewClient.onReceivedSslError',
        'android.webkit.WebViewClient', function (clazz) {
            clazz.onReceivedSslError.implementation = function (view, handler, error) {
                console.log('[+] WebViewClient.onReceivedSslError: proceed (??)');
                handler.proceed();
                return;
            };
        });
}

// ---------------------------------------------------------------------------
// Cordova ???? / Whitelist ??
// ---------------------------------------------------------------------------
function hookCordovaWhitelist() {
    console.log('\n--- [2] Cordova Whitelist / ???? ---');

    tryHookJava('CordovaWhitelist shouldAllowNavigation',
        'org.apache.cordova.Whitelist', function (clazz) {
            try {
                clazz.shouldAllowNavigation.implementation = function (url) {
                    console.log('[+] Whitelist.shouldAllowNavigation: true (' + url + ')');
                    return true;
                };
            } catch (e) {}
            try {
                clazz.shouldAllowRequest.implementation = function (url) {
                    console.log('[+] Whitelist.shouldAllowRequest: true (' + url + ')');
                    return true;
                };
            } catch (e) {}
            try {
                clazz.shouldInterruptLoadRequest.implementation = function (url) {
                    console.log('[+] Whitelist.shouldInterruptLoadRequest: false (' + url + ')');
                    return false;
                };
            } catch (e) {}
        });

    // Cordova 10+ WhititelistPlugin
    tryHookJava('WhitelistPlugin',
        'org.apache.cordova.whitelist.WhitelistPlugin', function (clazz) {
            try {
                clazz.shouldAllowNavigation.implementation = function (url) {
                    console.log('[+] WhitelistPlugin.shouldAllowNavigation: true (' + url + ')');
                    return true;
                };
            } catch (e) {}
            try {
                clazz.shouldAllowRequest.implementation = function (url) {
                    console.log('[+] WhitelistPlugin.shouldAllowRequest: true (' + url + ')');
                    return true;
                };
            } catch (e) {}
        });
}

// ---------------------------------------------------------------------------
// Cordova ????????
// ---------------------------------------------------------------------------
function hookCordovaPlugins() {
    console.log('\n--- [3] Cordova ?????? ---');

    // cordova-plugin-certificates (SSLCertificateChecker)
    tryHookJava('SSLCertificateChecker',
        'nl.xservices.plugins.SSLCertificateChecker', function (clazz) {
            try {
                var overloads = clazz.execute.overloads;
                for (var i = 0; i < overloads.length; i++) {
                    overloads[i].implementation = function (action, args, callbackId) {
                        console.log('[+] SSLCertificateChecker.execute: ?? true (' + action + ')');
                        // ?? PluginResult OK = true
                        var PluginResult = Java.use('org.apache.cordova.PluginResult');
                        var Status = Java.use('org.apache.cordova.PluginResult$Status');
                        return PluginResult.$new(Status.OK, 'true');
                    };
                }
            } catch (e) {
                console.log('  (execute hook: ' + e.message + ')');
            }
        });

    // cordova-plugin-advanced-http (Native HTTP) - ????
    tryHookJava('CordovaHttpPlugin',
        'com.silkimen.http.CordovaHttpPlugin', function (clazz) {
            // disable cert validation ??
            try {
                var overloads = clazz.execute.overloads;
                for (var i = 0; i < overloads.length; i++) {
                    overloads[i].implementation = function (action, args, callbackId) {
                        console.log('[+] CordovaHttpPlugin.execute: ?? (' + action + ')');
                        return this.execute(action, args, callbackId);
                    };
                }
            } catch (e) {}
        });

    // com.silkimen.http ?? TLS ?? (advanced-http ??)
    tryHookJava('HttpTLSSocketFactory',
        'com.silkimen.http.HttpTLSSocketFactory', function (clazz) {
            try {
                clazz.checkServerTrusted.implementation = function (chain, authType) {
                    console.log('[+] HttpTLSSocketFactory.checkServerTrusted: ??');
                };
            } catch (e) {}
        });

    tryHookJava('OkHttpTLSSocketFactory',
        'com.silkimen.http.OkHttpTLSSocketFactory', function (clazz) {
            try {
                clazz.checkServerTrusted.implementation = function (chain, authType) {
                    console.log('[+] OkHttpTLSSocketFactory.checkServerTrusted: ??');
                };
            } catch (e) {}
        });

    // IBM WorkLight / MobileFirst ????
    tryHookJava('WLCertificatePinningPlugin',
        'com.worklight.androidgap.plugin.WLCertificatePinningPlugin', function (clazz) {
            try {
                clazz.execute.implementation = function () {
                    console.log('[+] WLCertificatePinningPlugin.execute: ?? true');
                    return true;
                };
            } catch (e) {}
        });

    tryHookJava('HostNameVerifierWithCertificatePinning',
        'com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning',
        function (clazz) {
            try {
                var overloads = clazz.verify.overloads;
                for (var i = 0; i < overloads.length; i++) {
                    overloads[i].implementation = function () {
                        console.log('[+] WorkLight HostNameVerifier.verify: true');
                        return true;
                    };
                }
            } catch (e) {}
        });
}

// ---------------------------------------------------------------------------
// Ionic Native HTTP (@ionic-native/http) ??
// ---------------------------------------------------------------------------
function hookIonicNativeHTTP() {
    console.log('\n--- [4] Ionic Native HTTP ---');

    // @ionic-native/http ? Android ?? cordova-plugin-advanced-http
    // ???? hook ? OkHttp ??? Apache HttpClient
    tryHookJava('OkHttpStack',
        'com.silkimens.cordova.http.OkHttpStack', function (clazz) {
            try {
                var overloads = clazz.getOkHttpClient.overloads;
                for (var i = 0; i < overloads.length; i++) {
                    overloads[i].implementation = function () {
                        console.log('[+] OkHttpStack.getOkHttpClient: ???? client');
                        var client = this.getOkHttpClient.apply(this, arguments);
                        return client;
                    };
                }
            } catch (e) {}
        });

    // Apache HttpClient (advanced-http ? legacy ??)
    tryHookJava('ApacheStack',
        'com.silkimens.cordova.http.ApacheStack', function (clazz) {
            try {
                clazz.send.implementation = function () {
                    console.log('[+] ApacheStack.send: ??');
                    return this.send.apply(this, arguments);
                };
            } catch (e) {}
        });

    // ??: ???? TrustManager ??? HttpClient
    Java.perform(function () {
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var TrustManagerImpl = Java.registerClass({
                name: 'com.tma.cordova.DummyTrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            _keepAlive.trustManager = TrustManagerImpl;

            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                console.log('[+] SSLContext.init (Cordova): ?? DummyTrustManager');
                return this.init(km, [_keepAlive.trustManager.$new()], sr);
            };
            console.log('[*] Hook ???: SSLContext.init (Cordova ??)');
        } catch (e) {
            console.log('[!] Cordova TrustManager ????: ' + e.message);
        }

        // HttpsURLConnection ?? SSLSocketFactory
        try {
            var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (v) {
                console.log('[+] HttpsURLConnection.setDefaultHostnameVerifier: ??');
            };
            HttpsURLConnection.setSSLSocketFactory.implementation = function (f) {
                console.log('[+] HttpsURLConnection.setSSLSocketFactory: ??');
            };
        } catch (e) {}
    });
}

// ---------------------------------------------------------------------------
// Conscrypt TrustManagerImpl (WebView ????? TLS ?)
// ---------------------------------------------------------------------------
function hookConscryptTrustManager() {
    console.log('\n--- [5] Conscrypt TrustManagerImpl (WebView TLS) ---');

    tryHookJava('Conscrypt TrustManagerImpl',
        'com.android.org.conscrypt.TrustManagerImpl', function (clazz) {
            try {
                clazz.checkTrustedRecursive.implementation = function () {
                    console.log('[+] Conscrypt checkTrustedRecursive: ?????');
                    return Java.use('java.util.ArrayList').$new();
                };
            } catch (e) {}
            try {
                clazz.verifyChain.implementation = function (untrustedChain) {
                    console.log('[+] Conscrypt verifyChain: ?????');
                    return untrustedChain;
                };
            } catch (e) {}
            try {
                clazz.checkServerTrusted.overload(
                    '[Ljava.security.cert.X509Certificate;', 'java.lang.String'
                ).implementation = function (chain, authType) {
                    console.log('[+] Conscrypt checkServerTrusted: ??');
                    return Java.use('java.util.ArrayList').$new();
                };
            } catch (e) {}
        });

    // OpenSSLSocketImpl.verifyCertificateChain
    var sslSocketImpls = [
        'com.android.org.conscrypt.OpenSSLSocketImpl',
        'com.android.org.conscrypt.OpenSSLEngineSocketImpl',
        'com.android.org.conscrypt.ConscryptFileDescriptorSocket',
        'org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl'
    ];
    for (var i = 0; i < sslSocketImpls.length; i++) {
        tryHookJava(sslSocketImpls[i] + '.verifyCertificateChain',
            sslSocketImpls[i], function (clazz) {
                try {
                    clazz.verifyCertificateChain.implementation = function () {
                        console.log('[+] ' + clazz.$className + '.verifyCertificateChain: ??');
                    };
                } catch (e) {}
            });
    }
}

// ---------------------------------------------------------------------------
// Native ? SSL (Cordova ??????? libssl)
// ---------------------------------------------------------------------------
function hookNativeCordovaSSL() {
    console.log('\n--- [6] Native ? SSL (Cordova ????) ---');
    var nativeFuncs = ['SSL_CTX_set_verify', 'SSL_set_verify', 'SSL_get_verify_result'];
    for (var i = 0; i < nativeFuncs.length; i++) {
        try {
            var addr = Module.findExportByName(null, nativeFuncs[i]);
            if (addr === null) continue;
            (function (fn, a) {
                Interceptor.attach(a, {
                    onEnter: function (args) {
                        if (args[1]) args[1] = ptr(0);
                        if (args[2]) args[2] = ptr(0);
                        console.log('[+] Native ' + fn + ': mode -> 0');
                    }
                });
            })(nativeFuncs[i], addr);
            console.log('[*] Hook ??? (Native): ' + nativeFuncs[i] + ' @ ' + addr);
        } catch (e) {
            console.log('[-] Native ' + nativeFuncs[i] + ' hook ??: ' + e.message);
        }
    }
}

// ---------------------------------------------------------------------------
// ???
// ---------------------------------------------------------------------------
function main() {
    console.log('===========================================================');
    console.log(' TrustMeAlready - Cordova / Ionic SSL Bypass (Frida)');
    console.log(' ??: Cordova 8-12 / Ionic 3-7 / cordova-android 8-12');
    console.log('===========================================================');

    if (Java.available) {
        Java.perform(function () {
            console.log('[*] Java ????, ?? Java ? hook');
            hookCordovaWebViewClient();
            hookCordovaWhitelist();
            hookCordovaPlugins();
            hookIonicNativeHTTP();
            hookConscryptTrustManager();
        });
    } else {
        console.log('[-] Java ???, ??? Native ? hook');
    }

    hookNativeCordovaSSL();

    console.log('\n[*] Cordova / Ionic SSL Bypass ?????');
    console.log('===========================================================');
}

try {
    main();
} catch (e) {
    console.log('[!] ?????: ' + e.message);
    console.log(e.stack);
}
