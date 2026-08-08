/*
 * native_ssl_bypass.js
 * ---------------------------------------------------------------------------
 * ??: Native ? SSL/TLS ?????? (BoringSSL / OpenSSL / libssl)
 *
 * ????:
 *   - BoringSSL: SSL_CTX_set_verify, SSL_set_verify, SSL_get_verify_result,
 *                SSL_CTX_set_custom_verify, ssl_verify_peer_cert,
 *                ssl_crypto_x509_session_verify_cert_chain
 *   - OpenSSL:   SSL_CTX_set_verify, SSL_set_verify, SSL_get_verify_result,
 *                X509_verify_cert, SSL_CTX_set_cert_verify_callback
 *   - libssl.so / libboringssl.so / libconscrypt_jni.so ??????
 *   - ????: ???????, hook ???? verify / pin / check ? SSL ????
 *
 * ????/??:
 *   - Android 7.0+ (BoringSSL ?? Conscrypt ??????)
 *   - Android 5.0+ (OpenSSL ????)
 *   - ???? OpenSSL/BoringSSL ? NDK ??
 *
 * ????: frida -U -l native_ssl_bypass.js -f <package> --no-pause
 * ---------------------------------------------------------------------------
 */

'use strict';

// ????: ??? SSL ?? native ?
var SSL_LIBS = [
    'libssl.so',
    'libboringssl.so',
    'libcrypto.so',
    'libconscrypt_jni.so',
    'libssl_boringssl.so',
    'libboringssl_assume.a'
];

// ???? hook ? BoringSSL / OpenSSL ???
var EXACT_HOOK_NAMES = [
    'SSL_CTX_set_verify',
    'SSL_set_verify',
    'SSL_get_verify_result',
    'SSL_CTX_set_verify_depth',
    'SSL_CTX_set_custom_verify',
    'SSL_set_verify_callback',
    'X509_verify_cert',
    'SSL_CTX_set_cert_verify_callback'
];

// ???? hook ??? BoringSSL ???
var INTERNAL_HOOK_NAMES = [
    'ssl_verify_peer_cert',
    'ssl_crypto_x509_session_verify_cert_chain',
    'ssl_verify_cert_chain',
    'ssl_session_verify_chain',
    'SSL_add0_chain_cert',
    'tls12_check_peer_sigalg',
    'ssl_check_leaf_certificate'
];

// ??????? (???????)
var GENERIC_KEYWORDS = ['verify', 'pin', 'check', 'cert', 'trust'];

// X509_V_OK = 0, BoringSSL ? ssl_verify_result_t::ssl_verify_ok = 0
var SSL_VERIFY_OK = 0;
// SSL_VERIFY_NONE = 0 (BoringSSL / OpenSSL)
var SSL_VERIFY_NONE = 0x00;

// ---------------------------------------------------------------------------
// ????: ????????? (???????)
// ---------------------------------------------------------------------------
function findExportAcrossModules(name) {
    try {
        var addr = Module.findExportByName(null, name);
        if (addr !== null) {
            return addr;
        }
        for (var i = 0; i < SSL_LIBS.length; i++) {
            try {
                addr = Module.findExportByName(SSL_LIBS[i], name);
                if (addr !== null) {
                    return addr;
                }
            } catch (e) {
                // ?????, ??
            }
        }
    } catch (e) {
        console.log('[!] findExportAcrossModules("' + name + '") ??: ' + e.message);
    }
    return null;
}

// ---------------------------------------------------------------------------
// BoringSSL / OpenSSL: SSL_CTX_set_verify
// ??: void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, verify_callback cb);
// ??: ? mode ???? SSL_VERIFY_NONE (0)
// ---------------------------------------------------------------------------
function hookSSL_CTX_set_verify() {
    var addr = findExportAcrossModules('SSL_CTX_set_verify');
    if (addr === null) {
        console.log('[-] SSL_CTX_set_verify ???, ??');
        return;
    }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var originalMode = args[1].toInt32();
                console.log('[+] SSL_CTX_set_verify: mode ' + originalMode + ' -> 0 (SSL_VERIFY_NONE)');
                args[1] = ptr(SSL_VERIFY_NONE);
                args[2] = ptr(0); // callback = NULL
            }
        });
        console.log('[*] Hook ???: SSL_CTX_set_verify @ ' + addr);
    } catch (e) {
        console.log('[!] Hook SSL_CTX_set_verify ??: ' + e.message);
    }
}

// ---------------------------------------------------------------------------
// BoringSSL / OpenSSL: SSL_set_verify
// ??: void SSL_set_verify(SSL *s, int mode, verify_callback cb);
// ---------------------------------------------------------------------------
function hookSSL_set_verify() {
    var addr = findExportAcrossModules('SSL_set_verify');
    if (addr === null) {
        console.log('[-] SSL_set_verify ???, ??');
        return;
    }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var originalMode = args[1].toInt32();
                console.log('[+] SSL_set_verify: mode ' + originalMode + ' -> 0 (SSL_VERIFY_NONE)');
                args[1] = ptr(SSL_VERIFY_NONE);
                args[2] = ptr(0);
            }
        });
        console.log('[*] Hook ???: SSL_set_verify @ ' + addr);
    } catch (e) {
        console.log('[!] Hook SSL_set_verify ??: ' + e.message);
    }
}

// ---------------------------------------------------------------------------
// BoringSSL / OpenSSL: SSL_get_verify_result
// ??: long SSL_get_verify_result(const SSL *ssl);
// ??: ?? X509_V_OK (0)
// ---------------------------------------------------------------------------
function hookSSL_get_verify_result() {
    var addr = findExportAcrossModules('SSL_get_verify_result');
    if (addr === null) {
        console.log('[-] SSL_get_verify_result ???, ??');
        return;
    }
    try {
        var orig = new NativeFunction(addr, 'long', ['pointer']);
        Interceptor.replace(addr, new NativeCallback(function (ssl) {
            console.log('[+] SSL_get_verify_result: ?? X509_V_OK (0)');
            return SSL_VERIFY_OK;
        }, 'long', ['pointer']));
        console.log('[*] Hook ??? (replace): SSL_get_verify_result @ ' + addr);
    } catch (e) {
        console.log('[!] Hook SSL_get_verify_result ??: ' + e.message);
    }
}

// ---------------------------------------------------------------------------
// BoringSSL: SSL_CTX_set_custom_verify
// ??: void SSL_CTX_set_custom_verify(SSL_CTX *ctx, int mode,
//                                      enum ssl_verify_result_t (*callback)(
//                                          const SSL *ssl, uint8_t *out_alert));
// ??: mode ? 0, callback ? NULL
// ---------------------------------------------------------------------------
function hookSSL_CTX_set_custom_verify() {
    var addr = findExportAcrossModules('SSL_CTX_set_custom_verify');
    if (addr === null) {
        console.log('[-] SSL_CTX_set_custom_verify ???, ?? (???? BoringSSL)');
        return;
    }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var originalMode = args[1].toInt32();
                console.log('[+] SSL_CTX_set_custom_verify: mode ' + originalMode + ' -> 0');
                args[1] = ptr(0);
                args[2] = ptr(0);
            }
        });
        console.log('[*] Hook ???: SSL_CTX_set_custom_verify @ ' + addr);
    } catch (e) {
        console.log('[!] Hook SSL_CTX_set_custom_verify ??: ' + e.message);
    }
}

// ---------------------------------------------------------------------------
// OpenSSL: X509_verify_cert
// ??: int X509_verify_cert(X509_STORE_CTX *ctx);
// ??: ?? 1 (??)
// ---------------------------------------------------------------------------
function hookX509_verify_cert() {
    var addr = findExportAcrossModules('X509_verify_cert');
    if (addr === null) {
        console.log('[-] X509_verify_cert ???, ??');
        return;
    }
    try {
        Interceptor.replace(addr, new NativeCallback(function (ctx) {
            console.log('[+] X509_verify_cert: ?? 1 (????)');
            return 1;
        }, 'int', ['pointer']));
        console.log('[*] Hook ??? (replace): X509_verify_cert @ ' + addr);
    } catch (e) {
        console.log('[!] Hook X509_verify_cert ??: ' + e.message);
    }
}

// ---------------------------------------------------------------------------
// OpenSSL: SSL_CTX_set_cert_verify_callback
// ??: void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx,
//                                             int (*cb)(int, X509_STORE_CTX *),
//                                             void *arg);
// ??: ???????? 1 ???
// ---------------------------------------------------------------------------
function hookSSL_CTX_set_cert_verify_callback() {
    var addr = findExportAcrossModules('SSL_CTX_set_cert_verify_callback');
    if (addr === null) {
        console.log('[-] SSL_CTX_set_cert_verify_callback ???, ??');
        return;
    }
    try {
        // ???????? 1 ????? (int (*)(int, X509_STORE_CTX*))
        var fakeCallback = new NativeCallback(function (ok, ctx) {
            console.log('[+] SSL_CTX_set_cert_verify_callback: ???? 1 (??)');
            return 1;
        }, 'int', ['int', 'pointer']);
        Interceptor.attach(addr, {
            onEnter: function (args) {
                console.log('[+] SSL_CTX_set_cert_verify_callback: ???? -> ????');
                args[1] = fakeCallback;
            }
        });
        // ?? GC ??
        this._fakeCallback = fakeCallback;
        console.log('[*] Hook ???: SSL_CTX_set_cert_verify_callback @ ' + addr);
    } catch (e) {
        console.log('[!] Hook SSL_CTX_set_cert_verify_callback ??: ' + e.message);
    }
}

// ---------------------------------------------------------------------------
// BoringSSL ??: ssl_verify_peer_cert (Flutter / Conscrypt ??)
// ??: enum ssl_verify_result_t ssl_verify_peer_cert(const SSL *ssl);
// ?? 0 = ssl_verify_ok
// ---------------------------------------------------------------------------
function hookInternalVerifyFunction(name) {
    var addr = findExportAcrossModules(name);
    if (addr === null) {
        console.log('[-] ' + name + ' ???, ??');
        return;
    }
    try {
        // ?? replace, ????????????
        Interceptor.replace(addr, new NativeCallback(function (ssl) {
            console.log('[+] ' + name + ': ???? 0 (ssl_verify_ok)');
            return 0;
        }, 'int', ['pointer']));
        console.log('[*] Hook ??? (replace): ' + name + ' @ ' + addr);
    } catch (e) {
        // ?? replace ?? (???????), ??? attach ?? onLeave ?????
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    console.log('[+] ' + name + ': ???? (attach ??)');
                },
                onLeave: function (retval) {
                    retval.replace(0);
                    console.log('[+] ' + name + ': ??? -> 0');
                }
            });
            console.log('[*] Hook ??? (attach): ' + name + ' @ ' + addr);
        } catch (e2) {
            console.log('[!] Hook ' + name + ' ??: ' + e2.message);
        }
    }
}

// ---------------------------------------------------------------------------
// ????: ?????????, hook ???? verify/pin/check ? SSL ????
// ---------------------------------------------------------------------------
function hookGenericSSLFunctions() {
    var hookedCount = 0;
    for (var i = 0; i < SSL_LIBS.length; i++) {
        var libName = SSL_LIBS[i];
        var module = null;
        try {
            module = Process.findModuleByName(libName);
        } catch (e) {
            continue;
        }
        if (module === null) {
            continue;
        }
        console.log('[*] ???????: ' + libName + ' (base=' + module.base + ')');
        try {
            var exports = Module.enumerateExports(libName);
            for (var j = 0; j < exports.length; j++) {
                var exp = exports[j];
                var nameLower = exp.name.toLowerCase();
                // ?????? ssl/tls/cert/x509 ????? verify/pin/check ???
                var isSSLContext = nameLower.indexOf('ssl') >= 0 ||
                                   nameLower.indexOf('tls') >= 0 ||
                                   nameLower.indexOf('cert') >= 0 ||
                                   nameLower.indexOf('x509') >= 0;
                var hasKeyword = nameLower.indexOf('verify') >= 0 ||
                                 nameLower.indexOf('pin') >= 0 ||
                                 nameLower.indexOf('check') >= 0;
                if (isSSLContext && hasKeyword) {
                    try {
                        hookGenericExport(libName, exp.name, exp.address);
                        hookedCount++;
                    } catch (e) {
                        // ?? hook ???????
                    }
                }
            }
        } catch (e) {
            console.log('[!] ?? ' + libName + ' ?????: ' + e.message);
        }
    }
    console.log('[*] ????? hook ' + hookedCount + ' ? SSL ????');
}

// ---------------------------------------------------------------------------
// ?? hook: ????????? onLeave ???? 0 (????????????)
// ---------------------------------------------------------------------------
function hookGenericExport(libName, name, address) {
    // ????? hook ????, ????
    if (EXACT_HOOK_NAMES.indexOf(name) >= 0 || INTERNAL_HOOK_NAMES.indexOf(name) >= 0) {
        return;
    }
    try {
        Interceptor.attach(address, {
            onEnter: function (args) {
                // ??, ??????
            },
            onLeave: function (retval) {
                // ???????????? (? 0) ??????, ?? 0
                var val = retval.toInt32();
                if (val !== 0 && val > -1000 && val < 1000) {
                    retval.replace(0);
                    console.log('[+] ' + libName + ':' + name + ' ??? ' + val + ' -> 0');
                }
            }
        });
        console.log('    [generic] ' + libName + ':' + name + ' @ ' + address);
    } catch (e) {
        // ??
    }
}

// ---------------------------------------------------------------------------
// ???
// ---------------------------------------------------------------------------
function main() {
    console.log('===========================================================');
    console.log(' TrustMeAlready - Native SSL Bypass (Frida)');
    console.log(' ??: BoringSSL / OpenSSL / libssl ??????');
    console.log('===========================================================');
    console.log('[*] ????: ' + (Java.available ? 'Java + Native' : 'Pure Native'));
    console.log('[*] ???????: ' + Process.enumerateModules().length);

    // 1. BoringSSL / OpenSSL ?? hook
    console.log('\n--- [1] BoringSSL / OpenSSL ?? hook ---');
    hookSSL_CTX_set_verify();
    hookSSL_set_verify();
    hookSSL_get_verify_result();
    hookSSL_CTX_set_custom_verify();
    hookX509_verify_cert();
    hookSSL_CTX_set_cert_verify_callback();

    // 2. BoringSSL ??????
    console.log('\n--- [2] BoringSSL ?????? ---');
    for (var i = 0; i < INTERNAL_HOOK_NAMES.length; i++) {
        hookInternalVerifyFunction(INTERNAL_HOOK_NAMES[i]);
    }

    // 3. ????: ???????
    console.log('\n--- [3] ????: ?? SSL ????? ---');
    hookGenericSSLFunctions();

    console.log('\n[*] Native SSL Bypass ?????');
    console.log('===========================================================');
}

// ????? (Frida ???????)
try {
    main();
} catch (e) {
    console.log('[!] ?????: ' + e.message);
    console.log(e.stack);
}
