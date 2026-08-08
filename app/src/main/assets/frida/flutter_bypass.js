/*
 * flutter_bypass.js
 * ---------------------------------------------------------------------------
 * ??: Flutter / Dart ?? SSL Pinning ?? (Native ? BoringSSL)
 *
 * ????:
 *   Flutter ????? BoringSSL (????? libflutter.so), ?????
 *   TrustManager, ?? Java ?? SSL bypass ? Flutter ?????? Native
 *   ? hook libflutter.so ?? BoringSSL ?????
 *
 * ????:
 *   - Hook Flutter ?? (libflutter.so) ?? BoringSSL ??
 *   - ssl_verify_peer_cert (Flutter ??????)
 *   - SSL_CTX_set_custom_verify (BoringSSL ?????)
 *   - SSL_CTX_set_verify / SSL_set_verify / SSL_get_verify_result
 *   - ssl_crypto_x509_session_verify_cert_chain
 *   - dart:io HttpClient (Java ???, ???????? Java)
 *   - session_verify_x509_chain / ssl_verify_cert_chain (????)
 *
 * ????:
 *   - Flutter 1.x ~ 3.x (? 3.0 / 3.3 / 3.7 / 3.10 / 3.13 / 3.19 / 3.22 / 3.24)
 *   - Release / Debug ????
 *   - ?? arm64 / arm / x86_64 ??
 *
 * ????: frida -U -l flutter_bypass.js -f <package> --no-pause
 * ---------------------------------------------------------------------------
 */

'use strict';

// Flutter ??????? (?????)
var FLUTTER_LIB_NAMES = [
    'libflutter.so',
    'libflutter_arm32.so',
    'libflutter_arm64.so',
    'libflutter_x64.so'
];

// ?????? BoringSSL ??
var BORINGSSL_LIB_NAMES = [
    'libssl.so',
    'libboringssl.so',
    'libcrypto.so',
    'libconscrypt_jni.so'
];

// Flutter BoringSSL ??? hook ?????
var FLUTTER_VERIFY_FUNCS = [
    'ssl_verify_peer_cert',
    'ssl_crypto_x509_session_verify_cert_chain',
    'ssl_verify_cert_chain',
    'session_verify_x509_chain',
    'ssl_session_verify_chain',
    'SSL_CTX_set_custom_verify',
    'SSL_CTX_set_verify',
    'SSL_set_verify',
    'SSL_get_verify_result',
    'ssl_verify_leaf_cert',
    'ssl_check_leaf_certificate'
];

// ssl_verify_result_t::ssl_verify_ok = 0
var SSL_VERIFY_OK = 0;
var SSL_VERIFY_NONE = 0x00;

// ---------------------------------------------------------------------------
// ??: ??????????????
// ---------------------------------------------------------------------------
function findFlutterExport(name) {
    // ??? Flutter ?????
    for (var i = 0; i < FLUTTER_LIB_NAMES.length; i++) {
        try {
            var addr = Module.findExportByName(FLUTTER_LIB_NAMES[i], name);
            if (addr !== null) {
                return { address: addr, module: FLUTTER_LIB_NAMES[i] };
            }
        } catch (e) {
            // ?????
        }
    }
    // ????? BoringSSL/OpenSSL ???
    for (var j = 0; j < BORINGSSL_LIB_NAMES.length; j++) {
        try {
            var addr2 = Module.findExportByName(BORINGSSL_LIB_NAMES[j], name);
            if (addr2 !== null) {
                return { address: addr2, module: BORINGSSL_LIB_NAMES[j] };
            }
        } catch (e) {
            // ?????
        }
    }
    // ??????
    try {
        var addr3 = Module.findExportByName(null, name);
        if (addr3 !== null) {
            return { address: addr3, module: '<global>' };
        }
    } catch (e) {
        // ignore
    }
    return null;
}

// ---------------------------------------------------------------------------
// ?? Flutter ???? (libflutter.so ? app ???? dlopen)
// ---------------------------------------------------------------------------
function waitForFlutterLibrary(callback, attempts) {
    attempts = attempts || 0;
    if (attempts > 60) {
        console.log('[!] ?? libflutter.so ?? (60 ???), ???? hook ?? BoringSSL');
        callback(false);
        return;
    }
    var found = false;
    for (var i = 0; i < FLUTTER_LIB_NAMES.length; i++) {
        try {
            var mod = Process.findModuleByName(FLUTTER_LIB_NAMES[i]);
            if (mod !== null) {
                console.log('[*] ??? Flutter ??: ' + mod.name +
                            ' (base=' + mod.base + ', size=' + mod.size + ')');
                found = true;
                break;
            }
        } catch (e) {
            // ignore
        }
    }
    if (found) {
        callback(true);
    } else {
        setTimeout(function () {
            waitForFlutterLibrary(callback, attempts + 1);
        }, 500);
    }
}

// ---------------------------------------------------------------------------
// Hook: ssl_verify_peer_cert (Flutter ??????)
// ??: enum ssl_verify_result_t ssl_verify_peer_cert(const SSL *ssl);
// ?? 0 = ssl_verify_ok
// ---------------------------------------------------------------------------
function hookSslVerifyPeerCert() {
    var info = findFlutterExport('ssl_verify_peer_cert');
    if (info === null) {
        console.log('[-] ssl_verify_peer_cert ??? (????????, ???? hook)');
        return false;
    }
    try {
        Interceptor.replace(info.address, new NativeCallback(function (ssl) {
            console.log('[+] ssl_verify_peer_cert [' + info.module + ']: ???? ssl_verify_ok (0)');
            return SSL_VERIFY_OK;
        }, 'int', ['pointer']));
        console.log('[*] Hook ??? (replace): ssl_verify_peer_cert @ ' +
                    info.address + ' (' + info.module + ')');
        return true;
    } catch (e) {
        console.log('[!] Hook ssl_verify_peer_cert ??: ' + e.message);
        // ??: attach + onLeave
        try {
            Interceptor.attach(info.address, {
                onLeave: function (retval) {
                    retval.replace(SSL_VERIFY_OK);
                    console.log('[+] ssl_verify_peer_cert (attach): ??? -> 0');
                }
            });
            return true;
        } catch (e2) {
            console.log('[!] attach ???: ' + e2.message);
            return false;
        }
    }
}

// ---------------------------------------------------------------------------
// Hook: SSL_CTX_set_custom_verify (BoringSSL ?????, Flutter 3.x ??)
// ??: void SSL_CTX_set_custom_verify(SSL_CTX *ctx, int mode, callback cb);
// ---------------------------------------------------------------------------
function hookSSL_CTX_set_custom_verify() {
    var info = findFlutterExport('SSL_CTX_set_custom_verify');
    if (info === null) {
        console.log('[-] SSL_CTX_set_custom_verify ???, ??');
        return false;
    }
    try {
        Interceptor.attach(info.address, {
            onEnter: function (args) {
                var originalMode = args[1].toInt32();
                console.log('[+] SSL_CTX_set_custom_verify [' + info.module +
                            ']: mode ' + originalMode + ' -> 0, callback -> NULL');
                args[1] = ptr(0); // mode = SSL_VERIFY_NONE
                args[2] = ptr(0); // callback = NULL
            }
        });
        console.log('[*] Hook ???: SSL_CTX_set_custom_verify @ ' +
                    info.address + ' (' + info.module + ')');
        return true;
    } catch (e) {
        console.log('[!] Hook SSL_CTX_set_custom_verify ??: ' + e.message);
        return false;
    }
}

// ---------------------------------------------------------------------------
// Hook: SSL_CTX_set_verify / SSL_set_verify
// ---------------------------------------------------------------------------
function hookSSLVerifyFunctions() {
    var funcs = ['SSL_CTX_set_verify', 'SSL_set_verify'];
    var count = 0;
    for (var i = 0; i < funcs.length; i++) {
        var info = findFlutterExport(funcs[i]);
        if (info === null) {
            console.log('[-] ' + funcs[i] + ' ???, ??');
            continue;
        }
        try {
            Interceptor.attach(info.address, {
                onEnter: function (args) {
                    var mode = args[1].toInt32();
                    args[1] = ptr(SSL_VERIFY_NONE);
                    args[2] = ptr(0);
                    console.log('[+] ' + funcs[i] + ' [' + info.module +
                                ']: mode ' + mode + ' -> 0');
                }
            });
            console.log('[*] Hook ???: ' + funcs[i] + ' @ ' +
                        info.address + ' (' + info.module + ')');
            count++;
        } catch (e) {
            console.log('[!] Hook ' + funcs[i] + ' ??: ' + e.message);
        }
    }
    return count;
}

// ---------------------------------------------------------------------------
// Hook: SSL_get_verify_result
// ---------------------------------------------------------------------------
function hookSSL_get_verify_result() {
    var info = findFlutterExport('SSL_get_verify_result');
    if (info === null) {
        console.log('[-] SSL_get_verify_result ???, ??');
        return false;
    }
    try {
        Interceptor.replace(info.address, new NativeCallback(function (ssl) {
            console.log('[+] SSL_get_verify_result [' + info.module + ']: ?? X509_V_OK (0)');
            return 0;
        }, 'long', ['pointer']));
        console.log('[*] Hook ??? (replace): SSL_get_verify_result @ ' +
                    info.address + ' (' + info.module + ')');
        return true;
    } catch (e) {
        console.log('[!] Hook SSL_get_verify_result ??: ' + e.message);
        return false;
    }
}

// ---------------------------------------------------------------------------
// Hook: ssl_crypto_x509_session_verify_cert_chain ?????
// ---------------------------------------------------------------------------
function hookCertChainVerifyFunctions() {
    var funcs = [
        'ssl_crypto_x509_session_verify_cert_chain',
        'ssl_verify_cert_chain',
        'session_verify_x509_chain',
        'ssl_session_verify_chain'
    ];
    var count = 0;
    for (var i = 0; i < funcs.length; i++) {
        var info = findFlutterExport(funcs[i]);
        if (info === null) {
            console.log('[-] ' + funcs[i] + ' ???, ??');
            continue;
        }
        try {
            Interceptor.replace(info.address, new NativeCallback(function (ssl, hs) {
                console.log('[+] ' + funcs[i] + ' [' + info.module + ']: ?? 1 (????)');
                return 1;
            }, 'int', ['pointer', 'pointer']));
            console.log('[*] Hook ??? (replace): ' + funcs[i] + ' @ ' +
                        info.address + ' (' + info.module + ')');
            count++;
        } catch (e) {
            // ???????, ??? onLeave
            try {
                Interceptor.attach(info.address, {
                    onLeave: function (retval) {
                        var v = retval.toInt32();
                        if (v === 0) {
                            retval.replace(1);
                            console.log('[+] ' + funcs[i] + ' (attach): ??? 0 -> 1');
                        }
                    }
                });
                console.log('[*] Hook ??? (attach): ' + funcs[i] + ' @ ' +
                            info.address + ' (' + info.module + ')');
                count++;
            } catch (e2) {
                console.log('[!] Hook ' + funcs[i] + ' ??: ' + e2.message);
            }
        }
    }
    return count;
}

// ---------------------------------------------------------------------------
// ?? libflutter.so ??/???, hook ??? verify/cert/pin ???
// (???????????????)
// ---------------------------------------------------------------------------
function hookFlutterGenericVerify() {
    var count = 0;
    for (var i = 0; i < FLUTTER_LIB_NAMES.length; i++) {
        var mod = null;
        try {
            mod = Process.findModuleByName(FLUTTER_LIB_NAMES[i]);
        } catch (e) {
            continue;
        }
        if (mod === null) continue;
        console.log('[*] ?? Flutter ????: ' + mod.name);
        try {
            var exports = Module.enumerateExports(mod.name);
            for (var j = 0; j < exports.length; j++) {
                var exp = exports[j];
                var name = exp.name.toLowerCase();
                var hasVerify = name.indexOf('verify') >= 0 || name.indexOf('pin') >= 0;
                var isSSL = name.indexOf('ssl') >= 0 || name.indexOf('cert') >= 0 ||
                            name.indexOf('x509') >= 0;
                if (hasVerify && isSSL) {
                    try {
                        (function (fn, addr) {
                            Interceptor.attach(addr, {
                                onLeave: function (retval) {
                                    var v = retval.toInt32();
                                    if (v !== 1 && v > -100 && v < 100) {
                                        retval.replace(1);
                                        console.log('[+] generic ' + fn + ': ' + v + ' -> 1');
                                    }
                                }
                            });
                        })(exp.name, exp.address);
                        count++;
                        console.log('    [flutter-generic] ' + exp.name + ' @ ' + exp.address);
                    } catch (e) {
                        // ignore
                    }
                }
            }
        } catch (e) {
            console.log('[!] ?? ' + mod.name + ' ??: ' + e.message);
        }
    }
    console.log('[*] Flutter ?? hook ? ' + count + ' ???');
    return count;
}

// ---------------------------------------------------------------------------
// Java ???: dart:io HttpClient ?? (?? Flutter ????? Java ??)
// ---------------------------------------------------------------------------
function hookDartIOHttpClient() {
    if (!Java.available) {
        console.log('[-] Java ?????, ?? dart:io HttpClient Java ? hook');
        return;
    }
    Java.perform(function () {
        try {
            // Hook SecureSocket ?? (Flutter dart:io ?? Java ??)
            var secureSocket = Java.use('io.flutter.plugins.urllauncher.UrlLauncherPlugin');
            console.log('[*] UrlLauncherPlugin ??? (Flutter ??)');
        } catch (e) {
            // ????
        }

        try {
            // Flutter ???? SSL
            var sslPinningPlugin = Java.use('io.flutter.plugins.flutter_plugin_android_lifecycle');
            console.log('[*] Flutter lifecycle ?????');
        } catch (e) {
            // ignore
        }

        // ??? TrustManager ?? (?? Flutter ???? Java ???)
        try {
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var TrustManager = Java.use('javax.net.ssl.TrustManager');
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

            var TrustManagerImpl = Java.registerClass({
                name: 'com.tma.flutter.DummyTrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () {
                        return [];
                    }
                }
            });

            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                console.log('[+] SSLContext.init: ?? DummyTrustManager (Flutter Java ?)');
                var dummyArr = [TrustManagerImpl.$new()];
                return this.init(km, dummyArr, sr);
            };
            console.log('[*] Hook ???: SSLContext.init (Flutter Java ???)');
        } catch (e) {
            console.log('[!] Flutter Java ? TrustManager ????: ' + e.message);
        }

        // Hook HttpHostnameVerifier (dart:io ???????)
        try {
            var verifier = Java.use('io.flutter.util.HostnameVerifier');
            verifier.verify.implementation = function (hostname, session) {
                console.log('[+] Flutter HostnameVerifier.verify: ???? true (' + hostname + ')');
                return true;
            };
            console.log('[*] Hook ???: io.flutter.util.HostnameVerifier');
        } catch (e) {
            // ???????
        }
    });
}

// ---------------------------------------------------------------------------
// ???
// ---------------------------------------------------------------------------
function main() {
    console.log('===========================================================');
    console.log(' TrustMeAlready - Flutter / Dart SSL Bypass (Frida)');
    console.log(' ??: libflutter.so ?? BoringSSL ????');
    console.log(' ??: Flutter 1.x ~ 3.x');
    console.log('===========================================================');
    console.log('[*] ??: ' + Process.arch);
    console.log('[*] ????: ' + Process.pointerSize + ' ??');

    // ? hook ?? BoringSSL (??? libflutter.so ????)
    console.log('\n--- [1] ?? BoringSSL / OpenSSL hook (??) ---');
    hookSSL_CTX_set_custom_verify();
    hookSSLVerifyFunctions();
    hookSSL_get_verify_result();
    hookCertChainVerifyFunctions();
    hookSslVerifyPeerCert();

    // Java ???
    console.log('\n--- [2] dart:io HttpClient Java ??? hook ---');
    hookDartIOHttpClient();

    // ?? Flutter ?????????? hook
    console.log('\n--- [3] ?? libflutter.so ?? ---');
    waitForFlutterLibrary(function (flutterFound) {
        if (flutterFound) {
            console.log('[*] Flutter ?????, ????? hook');
            console.log('\n--- [4] Flutter ?? BoringSSL ?? hook ---');
            hookSslVerifyPeerCert();
            hookSSL_CTX_set_custom_verify();
            hookSSLVerifyFunctions();
            hookSSL_get_verify_result();
            hookCertChainVerifyFunctions();

            console.log('\n--- [5] Flutter ??????? hook ---');
            hookFlutterGenericVerify();
        } else {
            console.log('[!] ???? libflutter.so, ??? BoringSSL hook ??');
        }
        console.log('\n[*] Flutter SSL Bypass ?????');
        console.log('===========================================================');
    });
}

try {
    main();
} catch (e) {
    console.log('[!] ?????: ' + e.message);
    console.log(e.stack);
}
