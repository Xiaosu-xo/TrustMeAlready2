/*
 * hybrid_framework_bypass.js
 * ---------------------------------------------------------------------------
 * ??: ???? (Flutter / RN / Cordova / ??) ???????
 *
 * ???? (Native ???, Java ???):
 *   - Root ????: su / magisk / busybox / Superuser.apk ???????
 *   - Frida ????: frida-server ????, /proc/self/maps ?? frida/gum,
 *                    ??? frida-gum, /proc/self/status ?? TracerPid
 *   - ??????: ptrace ???, /proc/self/status TracerPid,
 *                   android.os.Debug.isDebuggerConnected, ro.debuggable
 *   - ???????: goldfish / ranchu / qemu / genymotion ???????
 *   - VPN / ??????: tun0 ??, HTTP_PROXY, ProxySelector
 *   - libc ??????: fopen / access / stat / open / readlink ?? su, magisk, frida
 *
 * ????:
 *   - Android 5.0 ~ 14 (API 21 ~ 34)
 *   - arm64-v8a / armeabi-v7a / x86 / x86_64
 *
 * ????: frida -U -l hybrid_framework_bypass.js -f <package> --no-pause
 * ---------------------------------------------------------------------------
 */

'use strict';

// ===========================================================================
// ??: ?????????????
// ===========================================================================

// Root ???? (??????)
var ROOT_PATHS = [
    '/system/bin/su',
    '/system/xbin/su',
    '/sbin/su',
    '/su/bin/su',
    '/system/sbin/su',
    '/vendor/bin/su',
    '/system/app/Superuser.apk',
    '/system/app/SuperSU',
    '/system/etc/init.d/99SuperSUDaemon',
    '/dev/com.koushikdutta.superuser.daemon/',
    '/system/xbin/busybox',
    '/system/bin/busybox',
    '/sbin/busybox',
    '/data/local/su',
    '/data/local/bin/su',
    '/data/local/xbin/su',
    '/system/sd/xbin/su',
    '/data/adb/magisk',
    '/data/adb/modules',
    '/sbin/.magisk',
    '/data/adb/ksu',
    '/data/adb/ksud',
    '/data/adb/ap',
    '/data/adb/apd',
    '/system/bin/.magisk',
    '/cache/.disable_magisk'
];

// Frida ????
var FRIDA_PATHS = [
    '/data/local/tmp/frida-server',
    '/data/local/tmp/re.frida.server',
    '/data/local/tmp/fs',
    '/data/local/tmp/gum-js-loop',
    '/data/local/tmp/gmain',
    '/data/local/tmp/linjector',
    '/data/local/tmp/frida-agent',
    '/system/bin/frida-server'
];

// Frida ????? (?? /proc/self/maps ??????)
var FRIDA_KEYWORDS = [
    'frida',
    'gum-js-loop',
    'gmain',
    'linjector',
    'pool-frida',
    're.frida',
    'frida-agent',
    'frida-gadget',
    'gadget'
];

// Magisk ?????
var MAGISK_KEYWORDS = [
    'magisk',
    'magiskinit',
    'magiskd',
    'magiskhide',
    'zygisk',
    'riru',
    'ksu',
    'ksud',
    'apd'
];

// ???????
var EMULATOR_PATHS = [
    '/dev/qemu_pipe',
    '/dev/socket/qemud',
    '/dev/qemu_trace',
    '/system/bin/qemu-props',
    '/sys/class/bdi/0:8',
    '/dev/socket/genyd',
    '/dev/socket/baseband_genyd',
    '/system/lib/libc_malloc_debug_qemu.so',
    '/sys/qemu_trace',
    '/system/bin/qemud'
];

// ????????
var EMULATOR_KEYWORDS = [
    'goldfish',
    'ranchu',
    'qemu',
    'genymotion',
    'vbox',
    'vbox86',
    'nox',
    'ttVM',
    'sdk_gphone',
    'generic_x86',
    'google_sdk'
];

// ??: ?????????????
var HIDDEN_PATHS = ROOT_PATHS.concat(FRIDA_PATHS).concat(EMULATOR_PATHS);

// ===========================================================================
// ????
// ===========================================================================

// ??????????
function shouldHidePath(path) {
    if (path === null || path === undefined) return false;
    var pathStr = path.toString();
    for (var i = 0; i < HIDDEN_PATHS.length; i++) {
        if (pathStr.indexOf(HIDDEN_PATHS[i]) >= 0) {
            return true;
        }
    }
    var lower = pathStr.toLowerCase();
    for (var m = 0; m < MAGISK_KEYWORDS.length; m++) {
        if (lower.indexOf(MAGISK_KEYWORDS[m]) >= 0) return true;
    }
    for (var f = 0; f < FRIDA_KEYWORDS.length; f++) {
        if (lower.indexOf(FRIDA_KEYWORDS[f]) >= 0) return true;
    }
    return false;
}

// ??????????????? (?? /proc ??)
function shouldFilterContent(content) {
    if (content === null || content === undefined) return false;
    var str = content.toString().toLowerCase();
    for (var i = 0; i < FRIDA_KEYWORDS.length; i++) {
        if (str.indexOf(FRIDA_KEYWORDS[i]) >= 0) return true;
    }
    for (var j = 0; j < MAGISK_KEYWORDS.length; j++) {
        if (str.indexOf(MAGISK_KEYWORDS[j]) >= 0) return true;
    }
    return false;
}

// ???? libc ??
function findLibcExport(name) {
    try {
        var addr = Module.findExportByName('libc.so', name);
        if (addr !== null) return addr;
        addr = Module.findExportByName(null, name);
        if (addr !== null) return addr;
    } catch (e) {
        console.log('[!] findLibcExport("' + name + '") ??: ' + e.message);
    }
    return null;
}

// ===========================================================================
// [1] Root ????: libc ???????? su/magisk/busybox
// ===========================================================================

// Hook fopen / fopen64
function hookFopen() {
    var funcs = ['fopen', 'fopen64'];
    for (var i = 0; i < funcs.length; i++) {
        var addr = findLibcExport(funcs[i]);
        if (addr === null) {
            console.log('[-] ' + funcs[i] + ' ???, ??');
            continue;
        }
        try {
            (function (fn, a) {
                Interceptor.attach(a, {
                    onEnter: function (args) {
                        this.path = args[0].readCString();
                        if (this.path && shouldHidePath(this.path)) {
                            this.hide = true;
                            console.log('[+] ' + fn + '("' + this.path + '"): ?? (?? NULL)');
                        }
                    },
                    onLeave: function (retval) {
                        if (this.hide) {
                            retval.replace(ptr(0));
                        }
                    }
                });
            })(funcs[i], addr);
            console.log('[*] Hook ???: ' + funcs[i] + ' @ ' + addr);
        } catch (e) {
            console.log('[!] Hook ' + funcs[i] + ' ??: ' + e.message);
        }
    }
}

// Hook access
function hookAccess() {
    var addr = findLibcExport('access');
    if (addr === null) {
        console.log('[-] access ???, ??');
        return;
    }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.path = args[0].readCString();
                if (this.path && shouldHidePath(this.path)) {
                    this.hide = true;
                    console.log('[+] access("' + this.path + '"): ?? (?? -1)');
                }
            },
            onLeave: function (retval) {
                if (this.hide) {
                    retval.replace(-1);
                }
            }
        });
        console.log('[*] Hook ???: access @ ' + addr);
    } catch (e) {
        console.log('[!] Hook access ??: ' + e.message);
    }
}

// Hook stat / stat64 / lstat / lstat64 / __xstat / fstatat
function hookStat() {
    var funcs = ['stat', 'stat64', 'lstat', 'lstat64', 'fstatat', 'fstatat64'];
    for (var i = 0; i < funcs.length; i++) {
        var addr = findLibcExport(funcs[i]);
        if (addr === null) {
            continue;
        }
        try {
            (function (fn, a) {
                Interceptor.attach(a, {
                    onEnter: function (args) {
                        // stat/lstat: path ? args[0]; fstatat: path ? args[1]
                        var pathArg = (fn === 'fstatat' || fn === 'fstatat64') ? args[1] : args[0];
                        try {
                            this.path = pathArg.readCString();
                        } catch (e) {
                            this.path = null;
                        }
                        if (this.path && shouldHidePath(this.path)) {
                            this.hide = true;
                            console.log('[+] ' + fn + '("' + this.path + '"): ?? (?? -1)');
                        }
                    },
                    onLeave: function (retval) {
                        if (this.hide) {
                            retval.replace(-1);
                        }
                    }
                });
            })(funcs[i], addr);
            console.log('[*] Hook ???: ' + funcs[i] + ' @ ' + addr);
        } catch (e) {
            console.log('[!] Hook ' + funcs[i] + ' ??: ' + e.message);
        }
    }
}

// Hook open / openat (????? open ????)
function hookOpen() {
    var funcs = ['open', 'openat'];
    for (var i = 0; i < funcs.length; i++) {
        var addr = findLibcExport(funcs[i]);
        if (addr === null) {
            continue;
        }
        try {
            (function (fn, a) {
                Interceptor.attach(a, {
                    onEnter: function (args) {
                        var pathArg = (fn === 'openat') ? args[1] : args[0];
                        try {
                            this.path = pathArg.readCString();
                        } catch (e) {
                            this.path = null;
                        }
                        if (this.path && shouldHidePath(this.path)) {
                            this.hide = true;
                            console.log('[+] ' + fn + '("' + this.path + '"): ?? (?? -1)');
                        }
                    },
                    onLeave: function (retval) {
                        if (this.hide) {
                            retval.replace(-1);
                        }
                    }
                });
            })(funcs[i], addr);
            console.log('[*] Hook ???: ' + funcs[i] + ' @ ' + addr);
        } catch (e) {
            console.log('[!] Hook ' + funcs[i] + ' ??: ' + e.message);
        }
    }
}

// Hook readlink / readlinkat (???? readlink ?? /proc/self/exe ?)
function hookReadlink() {
    var funcs = ['readlink', 'readlinkat'];
    for (var i = 0; i < funcs.length; i++) {
        var addr = findLibcExport(funcs[i]);
        if (addr === null) {
            continue;
        }
        try {
            (function (fn, a) {
                Interceptor.attach(a, {
                    onEnter: function (args) {
                        var pathArg = (fn === 'readlinkat') ? args[1] : args[0];
                        try {
                            this.path = pathArg.readCString();
                        } catch (e) {
                            this.path = null;
                        }
                        this.bufArg = (fn === 'readlinkat') ? args[2] : args[1];
                    },
                    onLeave: function (retval) {
                        // ? /proc/self/maps ?????????
                        if (this.path && this.path.indexOf('/proc/') >= 0 && retval.toInt32() > 0) {
                            try {
                                var content = this.bufArg.readCString(retval.toInt32());
                                if (content && shouldFilterContent(content)) {
                                    console.log('[+] ' + fn + '("' + this.path + '"): ????');
                                    // ????????? (????: ??)
                                    retval.replace(0);
                                }
                            } catch (e) {}
                        }
                    }
                });
            })(funcs[i], addr);
            console.log('[*] Hook ???: ' + funcs[i] + ' @ ' + addr);
        } catch (e) {
            console.log('[!] Hook ' + funcs[i] + ' ??: ' + e.message);
        }
    }
}

// Hook opendir (???? /system/xbin ????? su)
function hookOpendir() {
    var addr = findLibcExport('opendir');
    if (addr === null) {
        console.log('[-] opendir ???, ??');
        return;
    }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.path = args[0].readCString();
                if (this.path && shouldHidePath(this.path)) {
                    this.hide = true;
                    console.log('[+] opendir("' + this.path + '"): ?? (?? NULL)');
                }
            },
            onLeave: function (retval) {
                if (this.hide) {
                    retval.replace(ptr(0));
                }
            }
        });
        console.log('[*] Hook ???: opendir @ ' + addr);
    } catch (e) {
        console.log('[!] Hook opendir ??: ' + e.message);
    }
}

// ===========================================================================
// [2] Frida ????
// ===========================================================================

// Hook /proc/self/maps ?? (fopen + fgets ??)
// frida-server / frida-gadget ??????, ????? maps ??
function hookProcMapsRead() {
    // fgets: ? maps ????? frida/gum ??
    var fgetsAddr = findLibcExport('fgets');
    if (fgetsAddr === null) {
        console.log('[-] fgets ???, ?? maps ??');
        return;
    }
    try {
        Interceptor.attach(fgetsAddr, {
            onEnter: function (args) {
                this.buf = args[0];
            },
            onLeave: function (retval) {
                if (retval.isNull()) return;
                try {
                    var line = this.buf.readCString();
                    if (line && shouldFilterContent(line)) {
                        // ???????, ?? frida ??
                        var spaces = '';
                        for (var i = 0; i < line.length; i++) spaces += ' ';
                        this.buf.writeUtf8String(spaces);
                        console.log('[+] fgets maps: ?????');
                    }
                } catch (e) {}
            }
        });
        console.log('[*] Hook ???: fgets (proc maps ??) @ ' + fgetsAddr);
    } catch (e) {
        console.log('[!] Hook fgets ??: ' + e.message);
    }
}

// Hook pthread_setname_np / prctl: ?? frida ???
function hookThreadName() {
    var funcs = ['pthread_setname_np'];
    for (var i = 0; i < funcs.length; i++) {
        var addr = findLibcExport(funcs[i]);
        if (addr === null) continue;
        try {
            (function (fn, a) {
                Interceptor.attach(a, {
                    onEnter: function (args) {
                        try {
                            var name = args[1].readCString();
                            if (name && shouldFilterContent(name)) {
                                var fake = 'Binder:' + Math.floor(Math.random() * 9999);
                                args[1].writeUtf8String(fake);
                                console.log('[+] ' + fn + ': ??? "' + name + '" -> "' + fake + '"');
                            }
                        } catch (e) {}
                    }
                });
            })(funcs[i], addr);
            console.log('[*] Hook ???: ' + funcs[i] + ' @ ' + addr);
        } catch (e) {
            console.log('[!] Hook ' + funcs[i] + ' ??: ' + e.message);
        }
    }
}

// Hook connect: ??? frida ???? (27042/27043) ?????
function hookConnect() {
    var addr = findLibcExport('connect');
    if (addr === null) {
        console.log('[-] connect ???, ??');
        return;
    }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var sockaddr = args[1];
                    var family = sockaddr.readU16();
                    if (family === 2) { // AF_INET
                        var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                        if (port === 27042 || port === 27043) {
                            this.block = true;
                            console.log('[+] connect: ???? frida ?? ' + port);
                        }
                    }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (this.block) {
                    retval.replace(-1);
                }
            }
        });
        console.log('[*] Hook ???: connect (frida ????) @ ' + addr);
    } catch (e) {
        console.log('[!] Hook connect ??: ' + e.message);
    }
}

// Java ?: ?? frida ? Debug.isDebuggerConnected ? Runtime ??
function hookFridaJava() {
    if (!Java.available) return;
    Java.perform(function () {
        // ?? app ?? Runtime.exec ?? ps ?? frida-server
        try {
            var Runtime = Java.use('java.lang.Runtime');
            var execOverloads = Runtime.exec.overloads;
            for (var i = 0; i < execOverloads.length; i++) {
                (function (overload) {
                    overload.implementation = function () {
                        var cmd = arguments[0];
                        if (cmd && cmd.toString().indexOf('frida') >= 0) {
                            console.log('[+] Runtime.exec: ?? frida ????');
                            return overload.apply(this, arguments);
                        }
                        return overload.apply(this, arguments);
                    };
                })(execOverloads[i]);
            }
        } catch (e) {
            console.log('[!] Runtime.exec hook ??: ' + e.message);
        }
    });
}

// ===========================================================================
// [3] ??????
// ===========================================================================

// Hook ptrace: app ??? ptrace(PTRACE_TRACEME) ?????, ??????"??"
// ??: ?? ptrace ??, ?? 0 (??), ? app ??????
function hookPtrace() {
    var addr = findLibcExport('ptrace');
    if (addr === null) {
        console.log('[-] ptrace ???, ??');
        return;
    }
    try {
        Interceptor.replace(addr, new NativeCallback(function (request, pid, addr, data) {
            console.log('[+] ptrace(' + request + '): ?? 0 (????????)');
            return 0;
        }, 'long', ['int', 'int', 'pointer', 'pointer']));
        console.log('[*] Hook ??? (replace): ptrace @ ' + addr);
    } catch (e) {
        console.log('[!] Hook ptrace ??: ' + e.message);
    }
}

// Hook /proc/self/status ??: ?? TracerPid = 0
function hookProcStatusRead() {
    // ?? fgets ?? status ?, ? TracerPid ????? 0
    var fgetsAddr = findLibcExport('fgets');
    if (fgetsAddr === null) return;
    try {
        Interceptor.attach(fgetsAddr, {
            onEnter: function (args) {
                this.buf = args[0];
            },
            onLeave: function (retval) {
                if (retval.isNull()) return;
                try {
                    var line = this.buf.readCString();
                    if (line && line.indexOf('TracerPid') >= 0) {
                        var fake = 'TracerPid:\t0\n';
                        this.buf.writeUtf8String(fake);
                        console.log('[+] fgets /proc/status: TracerPid -> 0');
                    }
                } catch (e) {}
            }
        });
    } catch (e) {
        console.log('[!] fgets status hook ??: ' + e.message);
    }
}

// Java ?: Debug.isDebuggerConnected / ro.debuggable
function hookDebugJava() {
    if (!Java.available) return;
    Java.perform(function () {
        try {
            var Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.implementation = function () {
                console.log('[+] Debug.isDebuggerConnected: ?? false');
                return false;
            };
            console.log('[*] Hook ???: android.os.Debug.isDebuggerConnected');
        } catch (e) {
            console.log('[!] Debug.isDebuggerConnected hook ??: ' + e.message);
        }

        // ActivityManager.isUserAMonkey (???????????)
        try {
            var ActivityManager = Java.use('android.app.ActivityManager');
            ActivityManager.isUserAMonkey.implementation = function () {
                console.log('[+] ActivityManager.isUserAMonkey: ?? false');
                return false;
            };
        } catch (e) {}
    });
}

// ===========================================================================
// [4] ???????
// ===========================================================================

// Java ?: Build ????
function hookEmulatorJava() {
    if (!Java.available) return;
    Java.perform(function () {
        try {
            var Build = Java.use('android.os.Build');
            var props = ['FINGERPRINT', 'MODEL', 'PRODUCT', 'BRAND', 'MANUFACTURER', 'HARDWARE'];
            for (var i = 0; i < props.length; i++) {
                (function (propName) {
                    var origVal = Build[propName].value;
                    var isEmu = false;
                    var lower = ('' + origVal).toLowerCase();
                    for (var k = 0; k < EMULATOR_KEYWORDS.length; k++) {
                        if (lower.indexOf(EMULATOR_KEYWORDS[k]) >= 0) {
                            isEmu = true;
                            break;
                        }
                    }
                    if (isEmu) {
                        // ????????
                        var fakeMap = {
                            'FINGERPRINT': 'samsung/o1sxxx/o1s:13/TP1A.220624.014/S908EXXS5DWK1:user/release-keys',
                            'MODEL': 'SM-S908E',
                            'PRODUCT': 'o1sxxx',
                            'BRAND': 'samsung',
                            'MANUFACTURER': 'samsung',
                            'HARDWARE': 'qcom'
                        };
                        Build[propName].value = fakeMap[propName];
                        console.log('[+] Build.' + propName + ': "' + origVal + '" -> "' + fakeMap[propName] + '"');
                    }
                })(props[i]);
            }
        } catch (e) {
            console.log('[!] Build ?? hook ??: ' + e.message);
        }

        // TelephonyManager.getDeviceId / getNetworkOperatorName
        try {
            var TelephonyManager = Java.use('android.telephony.TelephonyManager');
            TelephonyManager.getNetworkOperatorName.implementation = function () {
                var orig = this.getNetworkOperatorName();
                if (('' + orig).toLowerCase().indexOf('android') >= 0 ||
                    ('' + orig).length === 0) {
                    console.log('[+] TelephonyManager.getNetworkOperatorName: ??');
                    return '310260';
                }
                return orig;
            };
        } catch (e) {}
    });
}

// Native ?: __system_property_get ???????
function hookSystemProperty() {
    var addr = findLibcExport('__system_property_get');
    if (addr === null) {
        console.log('[-] __system_property_get ???, ??');
        return;
    }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.name = args[0].readCString();
                this.valueBuf = args[1];
            },
            onLeave: function (retval) {
                if (!this.name) return;
                var emuProps = {
                    'ro.kernel.qemu': '0',
                    'ro.kernel.qemu.gles': '0',
                    'ro.hardware': 'qcom',
                    'ro.product.model': 'SM-S908E',
                    'ro.product.brand': 'samsung',
                    'ro.product.device': 'o1s',
                    'ro.product.name': 'o1sxxx',
                    'ro.build.fingerprint': 'samsung/o1sxxx/o1s:13/TP1A.220624.014/S908EXXS5DWK1:user/release-keys',
                    'ro.boot.hardware': 'qcom',
                    'init.svc.qemud': '',
                    'init.svc.qemu-props': '',
                    'qemu.hw.mainkeys': '',
                    'qemu.sf.fake_camera': ''
                };
                if (emuProps.hasOwnProperty(this.name)) {
                    var fake = emuProps[this.name];
                    this.valueBuf.writeUtf8String(fake);
                    console.log('[+] __system_property_get("' + this.name + '"): "' + fake + '"');
                }
            }
        });
        console.log('[*] Hook ???: __system_property_get @ ' + addr);
    } catch (e) {
        console.log('[!] Hook __system_property_get ??: ' + e.message);
    }
}

// ===========================================================================
// [5] VPN / ??????
// ===========================================================================

// Java ?: NetworkInterface ???? tun0
function hookVPNJava() {
    if (!Java.available) return;
    Java.perform(function () {
        try {
            var NetworkInterface = Java.use('java.net.NetworkInterface');
            NetworkInterface.getNetworkInterfaces.implementation = function () {
                var enums = this.getNetworkInterfaces();
                var list = Java.use('java.util.Collections').list(enums);
                var filtered = Java.use('java.util.ArrayList').$new();
                var it = list.iterator();
                while (it.hasNext()) {
                    var ni = it.next();
                    var name = '' + ni.getName();
                    var lower = name.toLowerCase();
                    if (lower.indexOf('tun') >= 0 || lower.indexOf('ppp') >= 0 ||
                        lower.indexOf('tap') >= 0) {
                        console.log('[+] NetworkInterface: ?? ' + name + ' (VPN)');
                    } else {
                        filtered.add(ni);
                    }
                }
                return Java.use('java.util.Collections').enumeration(filtered);
            };
            console.log('[*] Hook ???: NetworkInterface.getNetworkInterfaces (VPN ??)');
        } catch (e) {
            console.log('[!] NetworkInterface hook ??: ' + e.message);
        }

        // ProxySelector / System.getProperty("http.proxyHost")
        try {
            var System = Java.use('java.lang.System');
            var origGetProp = System.getProperty.overload('java.lang.String');
            origGetProp.implementation = function (key) {
                if (key === 'http.proxyHost' || key === 'https.proxyHost' ||
                    key === 'http.proxyPort' || key === 'https.proxyPort') {
                    console.log('[+] System.getProperty("' + key + '"): ?? null (????)');
                    return null;
                }
                return origGetProp.call(this, key);
            };
            console.log('[*] Hook ???: System.getProperty (????)');
        } catch (e) {
            console.log('[!] System.getProperty hook ??: ' + e.message);
        }

        // ConnectivityManager.getNetworkCapabilities / VPN_TRANSPORT
        try {
            var NetworkCapabilities = Java.use('android.net.NetworkCapabilities');
            NetworkCapabilities.hasTransport.implementation = function (transport) {
                // TRANSPORT_VPN = 4
                if (transport === 4) {
                    console.log('[+] NetworkCapabilities.hasTransport(VPN): ?? false');
                    return false;
                }
                return this.hasTransport(transport);
            };
            console.log('[*] Hook ???: NetworkCapabilities.hasTransport (VPN)');
        } catch (e) {
            console.log('[!] NetworkCapabilities hook ??: ' + e.message);
        }
    });
}

// Native ?: getifaddrs ?? tun0 ??
function hookGetifaddrs() {
    var addr = findLibcExport('getifaddrs');
    if (addr === null) {
        console.log('[-] getifaddrs ???, ??');
        return;
    }
    try {
        Interceptor.attach(addr, {
            onLeave: function (retval) {
                console.log('[*] getifaddrs ?? (VPN ????? Java ?????)');
            }
        });
        console.log('[*] Hook ???: getifaddrs @ ' + addr);
    } catch (e) {
        console.log('[!] Hook getifaddrs ??: ' + e.message);
    }
}

// ===========================================================================
// [6] Root ??: Java ??? (Runtime.exec("su"), which ??)
// ===========================================================================

function hookRootJava() {
    if (!Java.available) return;
    Java.perform(function () {
        // Runtime.exec("su") / Runtime.exec(["su", "-c", ...])
        try {
            var Runtime = Java.use('java.lang.Runtime');
            var execStrOverload = Runtime.exec.overload('java.lang.String');
            execStrOverload.implementation = function (cmd) {
                if (cmd && (('' + cmd).indexOf('su') >= 0 ||
                            ('' + cmd).indexOf('which') >= 0 ||
                            ('' + cmd).indexOf('busybox') >= 0 ||
                            ('' + cmd).indexOf('magisk') >= 0)) {
                    console.log('[+] Runtime.exec("' + cmd + '"): ?? root ??');
                    // ?? IOException ?? su ???
                    var IOException = Java.use('java.io.IOException');
                    throw IOException.$new('Permission denied');
                }
                return execStrOverload.call(this, cmd);
            };
            console.log('[*] Hook ???: Runtime.exec(String) (root ??)');
        } catch (e) {
            console.log('[!] Runtime.exec(String) hook ??: ' + e.message);
        }

        // Runtime.exec(String[])
        try {
            var execArrOverload = Runtime.exec.overload('[Ljava.lang.String;');
            execArrOverload.implementation = function (cmds) {
                if (cmds) {
                    for (var i = 0; i < cmds.length; i++) {
                        var c = '' + cmds[i];
                        if (c.indexOf('su') >= 0 || c.indexOf('busybox') >= 0 ||
                            c.indexOf('magisk') >= 0) {
                            console.log('[+] Runtime.exec([..]): ?? root ??');
                            var IOException = Java.use('java.io.IOException');
                            throw IOException.$new('Permission denied');
                        }
                    }
                }
                return execArrOverload.call(this, cmds);
            };
            console.log('[*] Hook ???: Runtime.exec(String[]) (root ??)');
        } catch (e) {
            console.log('[!] Runtime.exec(String[]) hook ??: ' + e.message);
        }

        // PackageManager ?? root ????
        try {
            var PM = Java.use('android.app.ApplicationPackageManager');
            PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (name, flags) {
                var rootPkgs = ['com.topjohnwu.magisk', 'eu.chainfire.supersu',
                                'com.koushikdutta.superuser', 'com.thirdparty.superuser',
                                'com.kingouser.com', 'com.kingroot.kinguser'];
                for (var i = 0; i < rootPkgs.length; i++) {
                    if (('' + name) === rootPkgs[i]) {
                        console.log('[+] PackageManager.getPackageInfo("' + name + '"): ? NameNotFoundException');
                        var NNFE = Java.use('android.content.pm.PackageManager$NameNotFoundException');
                        throw NNFE.$new(name);
                    }
                }
                return this.getPackageInfo(name, flags);
            };
            console.log('[*] Hook ???: PackageManager.getPackageInfo (root ????)');
        } catch (e) {
            console.log('[!] PackageManager hook ??: ' + e.message);
        }
    });
}

// ===========================================================================
// ???
// ===========================================================================

function main() {
    console.log('===========================================================');
    console.log(' TrustMeAlready - Hybrid Framework Detection Bypass');
    console.log(' Root / Frida / Debug / Emulator / VPN / Proxy');
    console.log('===========================================================');
    console.log('[*] ??: ' + Process.arch + ', PID: ' + Process.id);

    // [1] Root ???? (libc ????)
    console.log('\n--- [1] Root ???? (libc ??????) ---');
    hookFopen();
    hookAccess();
    hookStat();
    hookOpen();
    hookReadlink();
    hookOpendir();

    // [2] Frida ????
    console.log('\n--- [2] Frida ???? ---');
    hookProcMapsRead();
    hookThreadName();
    hookConnect();

    // [3] ??????
    console.log('\n--- [3] ?????? ---');
    hookPtrace();
    hookProcStatusRead();

    // [4] ???????
    console.log('\n--- [4] ??????? ---');
    hookSystemProperty();

    // [5] VPN / ??????
    console.log('\n--- [5] VPN / ?????? ---');
    hookGetifaddrs();

    // Java ???
    if (Java.available) {
        console.log('\n--- [6] Java ??? hook ---');
        Java.perform(function () {
            hookFridaJava();
            hookDebugJava();
            hookEmulatorJava();
            hookVPNJava();
            hookRootJava();
        });
    } else {
        console.log('[-] Java ???, ?? Java ? hook');
    }

    console.log('\n[*] Hybrid Framework Detection Bypass ?????');
    console.log('===========================================================');
}

try {
    main();
} catch (e) {
    console.log('[!] ?????: ' + e.message);
    console.log(e.stack);
}
