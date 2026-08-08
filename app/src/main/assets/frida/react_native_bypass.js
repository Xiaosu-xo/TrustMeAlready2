/*
 * react_native_bypass.js
 * ---------------------------------------------------------------------------
 * ??: React Native ?? SSL Pinning / ??????
 *
 * ????:
 *   React Native ? Android ????? OkHttp ??????, ??????
 *   Flipper ?????????RN ????? Cronet (Chromium ???) ?
 *   ??? networking ???????? Java ?? Native ??
 *
 * ????:
 *   - Flipper ???? / FlipperOkHttpInterceptor
 *   - ReactNativeOkHttpProvider (RN 0.60+ ?????)
 *   - RN ?????????? (NetworkModule / OkHttpNetworkAgent)
 *   - RCTNetworkTask / RCTNetworking
 *   - okhttp3 CertificatePinner (RN ?? OkHttp)
 *   - Cronet (RN Chromium ???, libnetassists.so / libcronet.so)
 *   - TrustKit / CertPinning (??? RN ???)
 *
 * ????:
 *   - React Native 0.59 ~ 0.74
 *   - New Architecture (Fabric / TurboModules) 0.68+
 *   - Old Architecture (Bridge)
 *
 * ????: frida -U -l react_native_bypass.js -f <package> --no-pause
 * ---------------------------------------------------------------------------
 */

'use strict';

// ?? GC ???????
var _keepAlive = {};

// ---------------------------------------------------------------------------
// ?? Java hook ??: ????, ???? hook ??????
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
// Flipper ??????
// Flipper ? debug ???? OkHttp ????????????
// ---------------------------------------------------------------------------
function hookFlipper() {
    console.log('\n--- [1] Flipper ???? ---');

    // FlipperOkHttpInterceptor
    tryHookJava('FlipperOkHttpInterceptor',
        'com.facebook.flipper.plugins.network.FlipperOkHttpInterceptor', function (clazz) {
            clazz.intercept.implementation = function (chain) {
                console.log('[+] FlipperOkHttpInterceptor.intercept: ????????');
                var request = chain.request();
                return chain.proceed(request);
            };
        });

    // FlipperNetworkPlugin
    tryHookJava('FlipperNetworkPlugin',
        'com.facebook.flipper.plugins.network.NetworkFlipperPlugin', function (clazz) {
            // ????? reportRequest/reportResponse, ???????
            try {
                clazz.reportRequest.implementation = function (req) {
                    console.log('[+] Flipper reportRequest: ??');
                    return;
                };
            } catch (e) {}
        });

    // Flipper ????: ????? SSL ??
    tryHookJava('FlipperSecurity',
        'com.facebook.flipper.android.utils.FlipperCertificateHelper', function (clazz) {
            try {
                clazz.isCertificatePinningEnabled.implementation = function () {
                    console.log('[+] Flipper isCertificatePinningEnabled: ?? false');
                    return false;
                };
            } catch (e) {}
            try {
                clazz.verifyHostname.implementation = function (hostname) {
                    console.log('[+] Flipper verifyHostname: ?? true (' + hostname + ')');
                    return true;
                };
            } catch (e) {}
        });
}

// ---------------------------------------------------------------------------
// ReactNativeOkHttpProvider ?? (RN 0.60+ ?? OkHttp ???)
// ---------------------------------------------------------------------------
function hookReactNativeOkHttpProvider() {
    console.log('\n--- [2] ReactNativeOkHttpProvider ---');

    tryHookJava('OkHttpClientProvider',
        'com.facebook.react.modules.network.OkHttpClientProvider', function (clazz) {
            // getOkHttpClient / createClient: ??????
            try {
                clazz.getOkHttpClient.implementation = function () {
                    console.log('[+] OkHttpClientProvider.getOkHttpClient: ???? client');
                    return this.getOkHttpClient();
                };
            } catch (e) {}
        });

    // ???? OkHttpClient.Builder ??????
    tryHookJava('OkHttpClientBuilder',
        'okhttp3.OkHttpClient$Builder', function (clazz) {
            try {
                clazz.certificatePinner.overload('okhttp3.CertificatePinner')
                    .implementation = function (pinner) {
                        console.log('[+] OkHttp.Builder.certificatePinner: ???? pinner');
                        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                        var emptyPinner = CertificatePinner.EMPTY;
                        return this.certificatePinner(emptyPinner);
                    };
            } catch (e) {
                console.log('  (certificatePinner hook: ' + e.message + ')');
            }

            try {
                clazz.hostnameVerifier.overload('javax.net.ssl.HostnameVerifier')
                    .implementation = function (verifier) {
                        console.log('[+] OkHttp.Builder.hostnameVerifier: ????? verifier');
                        return this.hostnameVerifier(this.dummyHostnameVerifier());
                    };
                // ??????
            } catch (e) {
                console.log('  (hostnameVerifier hook: ' + e.message + ')');
            }
        });

    // ???? HostnameVerifier ? SSLSocketFactory
    Java.perform(function () {
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var TrustManagerImpl = Java.registerClass({
                name: 'com.tma.rn.DummyTrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            _keepAlive.trustManager = TrustManagerImpl;

            var HostnameVerifierImpl = Java.registerClass({
                name: 'com.tma.rn.DummyHostnameVerifier',
                implements: [Java.use('javax.net.ssl.HostnameVerifier')],
                methods: {
                    verify: function (hostname, session) {
                        console.log('[+] RN HostnameVerifier.verify: true (' + hostname + ')');
                        return true;
                    }
                }
            });
            _keepAlive.hostnameVerifier = HostnameVerifierImpl;

            // ?? hook Builder ???????
            var Builder = Java.use('okhttp3.OkHttpClient$Builder');
            Builder.sslSocketFactory.overload(
                'javax.net.ssl.SSLSocketFactory',
                'javax.net.ssl.X509TrustManager'
            ).implementation = function (ssf, tm) {
                console.log('[+] OkHttp.Builder.sslSocketFactory: ?? DummyTrustManager');
                var dummy = _keepAlive.trustManager.$new();
                return this.sslSocketFactory(ssf, dummy);
            };

            Builder.hostnameVerifier.overload('javax.net.ssl.HostnameVerifier')
                .implementation = function (verifier) {
                    console.log('[+] OkHttp.Builder.hostnameVerifier: ?? DummyHostnameVerifier');
                    return this.hostnameVerifier(_keepAlive.hostnameVerifier.$new());
                };
        } catch (e) {
            console.log('[!] RN TrustManager/HostnameVerifier ????: ' + e.message);
        }
    });
}

// ---------------------------------------------------------------------------
// okhttp3 CertificatePinner.check ?? (RN ?? OkHttp)
// ---------------------------------------------------------------------------
function hookOkHttpCertificatePinner() {
    console.log('\n--- [3] okhttp3 CertificatePinner ---');

    tryHookJava('okhttp3 CertificatePinner.check', 'okhttp3.CertificatePinner', function (clazz) {
        // check$okhttp (Kotlin ?????)
        try {
            clazz['check$okhttp'].implementation = function (hostname, peerCertificates) {
                console.log('[+] CertificatePinner.check$okhttp: ?? (' + hostname + ')');
                return;
            };
        } catch (e) {}
        // check (????)
        try {
            var overloads = clazz.check.overloads;
            for (var i = 0; i < overloads.length; i++) {
                overloads[i].implementation = function () {
                    console.log('[+] CertificatePinner.check: ??');
                    return;
                };
            }
        } catch (e) {}
        // findMatchingPins
        try {
            var fpOverloads = clazz.findMatchingPins.overloads;
            for (var j = 0; j < fpOverloads.length; j++) {
                fpOverloads[j].implementation = function (hostname) {
                    console.log('[+] CertificatePinner.findMatchingPins: ??? (' + hostname + ')');
                    return Java.use('java.util.Collections').emptyList();
                };
            }
        } catch (e) {}
    });
}

// ---------------------------------------------------------------------------
// RCTNetworkTask / RCTNetworking ??
// ---------------------------------------------------------------------------
function hookRCTNetwork() {
    console.log('\n--- [4] RCTNetworkTask / RCTNetworking ---');

    tryHookJava('RCTNetworking',
        'com.facebook.react.modules.network.RCTNetworking', function (clazz) {
            // ????????????
            try {
                clazz.sendRequest.overload('java.lang.String', 'java.lang.String',
                    'com.facebook.react.bridge.ReadableMap', 'com.facebook.react.bridge.ReadableMap',
                    'java.lang.String', 'boolean', 'long').implementation = function () {
                    console.log('[+] RCTNetworking.sendRequest: ??');
                    return this.sendRequest.apply(this, arguments);
                };
            } catch (e) {}
        });

    tryHookJava('RCTNetworkTask',
        'com.facebook.react.modules.network.RCTNetworkTask', function (clazz) {
            try {
                clazz.onPreSslError.implementation = function (handler) {
                    console.log('[+] RCTNetworkTask.onPreSslError: proceed (?? SSL ??)');
                    try {
                        handler.proceed();
                    } catch (e) {}
                };
            } catch (e) {}
            try {
                clazz.onSslError.implementation = function (handler) {
                    console.log('[+] RCTNetworkTask.onSslError: proceed');
                    try { handler.proceed(); } catch (e) {}
                };
            } catch (e) {}
        });
}

// ---------------------------------------------------------------------------
// Cronet (RN Chromium ???) ??
// ---------------------------------------------------------------------------
function hookCronet() {
    console.log('\n--- [5] Cronet (Chromium ???) ---');

    tryHookJava('CronetEngine.Builder',
        'org.chromium.net.CronetEngine$Builder', function (clazz) {
            try {
                clazz.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function (val) {
                    console.log('[+] Cronet enablePublicKeyPinningBypass: ?? true');
                    return this.enablePublicKeyPinningBypassForLocalTrustAnchors(true);
                };
            } catch (e) {}
            try {
                var addPinsOverloads = clazz.addPublicKeyPins.overloads;
                for (var i = 0; i < addPinsOverloads.length; i++) {
                    addPinsOverloads[i].implementation = function () {
                        console.log('[+] Cronet addPublicKeyPins: ??????');
                        return this;
                    };
                }
            } catch (e) {}
        });

    // Native ? Cronet: libcronet.so ??????
    var cronetLibs = ['libcronet.so', 'libcronet.86.0.4240.198.so'];
    for (var i = 0; i < cronetLibs.length; i++) {
        try {
            var mod = Process.findModuleByName(cronetLibs[i]);
            if (mod === null) continue;
            console.log('[*] ??? Cronet ?: ' + mod.name);
            var exports = Module.enumerateExports(mod.name);
            for (var j = 0; j < exports.length; j++) {
                var n = exports[j].name.toLowerCase();
                if ((n.indexOf('verify') >= 0 || n.indexOf('cert') >= 0) &&
                    n.indexOf('ssl') >= 0) {
                    try {
                        (function (fn, addr) {
                            Interceptor.attach(addr, {
                                onLeave: function (retval) {
                                    var v = retval.toInt32();
                                    if (v !== 1 && v > -100 && v < 100) {
                                        retval.replace(1);
                                        console.log('[+] Cronet native ' + fn + ': ' + v + ' -> 1');
                                    }
                                }
                            });
                        })(exports[j].name, exports[j].address);
                    } catch (e) {}
                }
            }
        } catch (e) {
            // ignore
        }
    }
}

// ---------------------------------------------------------------------------
// ?????? (TrustKit ?) ? RN ???
// ---------------------------------------------------------------------------
function hookThirdPartyPinning() {
    console.log('\n--- [6] ?????? ---');

    tryHookJava('TrustKit OkHostnameVerifier',
        'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier', function (clazz) {
            try {
                var overloads = clazz.verify.overloads;
                for (var i = 0; i < overloads.length; i++) {
                    overloads[i].implementation = function () {
                        console.log('[+] TrustKit verify: ?? true');
                        return true;
                    };
                }
            } catch (e) {}
        });

    tryHookJava('TrustKit PinningTrustManager',
        'com.datatheorem.android.trustkit.pinning.PinningTrustManager', function (clazz) {
            try {
                clazz.checkServerTrusted.implementation = function (chain, authType) {
                    console.log('[+] TrustKit checkServerTrusted: ??');
                };
            } catch (e) {}
        });

    // Conscrypt TrustManagerImpl (RN ????? Conscrypt)
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
        });
}

// ---------------------------------------------------------------------------
// Native ?: RN ????? libssl.so / libokhttp.so
// ---------------------------------------------------------------------------
function hookNativeRNSSL() {
    console.log('\n--- [7] Native ? SSL (RN ???) ---');
    var nativeFuncs = [
        'SSL_CTX_set_verify',
        'SSL_set_verify',
        'SSL_get_verify_result',
        'SSL_CTX_set_custom_verify'
    ];
    for (var i = 0; i < nativeFuncs.length; i++) {
        try {
            var addr = Module.findExportByName(null, nativeFuncs[i]);
            if (addr === null) continue;
            (function (fn, a) {
                Interceptor.attach(a, {
                    onEnter: function (args) {
                        if (args[1]) {
                            args[1] = ptr(0); // SSL_VERIFY_NONE
                        }
                        if (args[2]) {
                            args[2] = ptr(0);
                        }
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
    console.log(' TrustMeAlready - React Native SSL Bypass (Frida)');
    console.log(' ??: React Native 0.59 ~ 0.74 (Bridge & Fabric)');
    console.log('===========================================================');

    if (Java.available) {
        Java.perform(function () {
            console.log('[*] Java ????, ?? Java ? hook');
            hookFlipper();
            hookReactNativeOkHttpProvider();
            hookOkHttpCertificatePinner();
            hookRCTNetwork();
            hookCronet();
            hookThirdPartyPinning();
        });
    } else {
        console.log('[-] Java ???, ??? Native ? hook');
    }

    hookNativeRNSSL();

    console.log('\n[*] React Native SSL Bypass ?????');
    console.log('===========================================================');
}

try {
    main();
} catch (e) {
    console.log('[!] ?????: ' + e.message);
    console.log(e.stack);
}
