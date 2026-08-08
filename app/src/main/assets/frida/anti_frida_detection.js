/*
 * Anti-Frida Detection Bypass - Native Layer (Optimized)
 *
 * PERFORMANCE FIX: Previous version hooked read() and strstr() GLOBALLY,
 * intercepting every single call in the app (thousands per second).
 * This caused severe lag and ANR (app freeze).
 *
 * This version uses fd-tracking: open() tracks which file descriptors
 * point to /proc files. read() only filters content for those tracked
 * fds (extremely rare). All other reads bypass with a single property
 * lookup - near-zero overhead.
 *
 * REMOVED expensive hooks: strstr(), pthread_getname_np(), dl_iterate_phdr
 * KEPT lightweight hooks: open() (track fds), close() (cleanup), connect()
 */

(function () {
    // Map of fd ? path for /proc files we want to filter
    var procFds = {};

    // Keywords to filter from /proc reads
    var FRIDA_KEYWORDS = ["frida", "gum-js-loop", "gmain", "linjector",
                          "pool-frida", "frida-agent"];

    // ==================================================================
    // 1. Hook open() - track file descriptors for /proc files
    // ==================================================================
    try {
        var openPtr = Module.findExportByName(null, "open");
        if (openPtr) {
            Interceptor.attach(openPtr, {
                onEnter: function (args) {
                    try {
                        var path = args[0].readUtf8String();
                        if (path && path.indexOf("/proc/") === 0) {
                            // Track /proc/self/maps, /proc/self/status,
                            // /proc/self/task, /proc/net/tcp, /proc/net/tcp6
                            if (path.indexOf("/maps") !== -1 ||
                                path.indexOf("/status") !== -1 ||
                                path.indexOf("/task") !== -1 ||
                                path.indexOf("/net/tcp") !== -1) {
                                this.isProcPath = true;
                                this.procPath = path;
                            }
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    try {
                        var fd = retval.toInt32();
                        if (this.isProcPath && fd >= 0) {
                            procFds[fd] = this.procPath;
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}

    // Also hook fopen() - some apps use fopen + fgets instead of open + read
    try {
        var fopenPtr = Module.findExportByName(null, "fopen");
        if (fopenPtr) {
            Interceptor.attach(fopenPtr, {
                onEnter: function (args) {
                    try {
                        var path = args[0].readUtf8String();
                        if (path && path.indexOf("/proc/") === 0) {
                            if (path.indexOf("/maps") !== -1 ||
                                path.indexOf("/status") !== -1 ||
                                path.indexOf("/task") !== -1 ||
                                path.indexOf("/net/tcp") !== -1) {
                                this.isProcPath = true;
                            }
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    // We can't easily track FILE* ? fd mapping here.
                    // fgets() hook below handles this by checking the
                    // line content directly (fgets is called less often
                    // than read(), so the overhead is acceptable).
                }
            });
        }
    } catch (e) {}

    // ==================================================================
    // 2. Hook read() - ONLY filter for tracked /proc fds
    //    Fast path: if fd not in procFds, return immediately.
    //    Slow path (rare): filter frida traces from /proc content.
    // ==================================================================
    try {
        var readPtr = Module.findExportByName(null, "read");
        if (readPtr) {
            Interceptor.attach(readPtr, {
                onEnter: function (args) {
                    this.fd = args[0].toInt32();
                    this.buf = args[1];
                    // Fast path: check if this fd is a tracked /proc file.
                    // This is a simple object property lookup - near zero cost.
                    this.isProc = procFds[this.fd] !== undefined;
                },
                onLeave: function (retval) {
                    // Fast path: skip non-/proc reads entirely
                    if (!this.isProc) return;

                    try {
                        var bytesRead = retval.toInt32();
                        if (bytesRead <= 0) return;

                        var content = this.buf.readUtf8String(bytesRead);
                        if (!content) return;

                        var modified = false;

                        // Filter frida/gum from /proc/maps
                        var hasFrida = false;
                        for (var i = 0; i < FRIDA_KEYWORDS.length; i++) {
                            if (content.indexOf(FRIDA_KEYWORDS[i]) !== -1) {
                                hasFrida = true;
                                break;
                            }
                        }

                        if (hasFrida) {
                            var lines = content.split("\n");
                            var filtered = [];
                            for (var j = 0; j < lines.length; j++) {
                                var line = lines[j].toLowerCase();
                                var skip = false;
                                for (var k = 0; k < FRIDA_KEYWORDS.length; k++) {
                                    if (line.indexOf(FRIDA_KEYWORDS[k]) !== -1) {
                                        skip = true;
                                        break;
                                    }
                                }
                                if (!skip) {
                                    filtered.push(lines[j]);
                                }
                            }
                            content = filtered.join("\n");
                            modified = true;
                        }

                        // Fix TracerPid in /proc/self/status
                        if (content.indexOf("TracerPid:") !== -1) {
                            content = content.replace(/TracerPid:\s*\d+/g, "TracerPid:\t0");
                            modified = true;
                        }

                        // Filter port 27042 (hex 69A2) from /proc/net/tcp
                        if (content.indexOf(":69a2") !== -1 || content.indexOf(":69A2") !== -1) {
                            var tcpLines = content.split("\n");
                            var tcpFiltered = [];
                            for (var t = 0; t < tcpLines.length; t++) {
                                var tcpLower = tcpLines[t].toLowerCase();
                                if (tcpLower.indexOf(":69a2") === -1 && tcpLower.indexOf(":69a3") === -1) {
                                    tcpFiltered.push(tcpLines[t]);
                                }
                            }
                            content = tcpFiltered.join("\n");
                            modified = true;
                        }

                        if (modified) {
                            var newBytes = [];
                            for (var c = 0; c < content.length; c++) {
                                newBytes.push(content.charCodeAt(c));
                            }
                            this.buf.writeByteArray(newBytes);
                            retval.replace(ptr(content.length));
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}

    // ==================================================================
    // 3. Hook fgets() - filter /proc reads via fopen+fgets path
    //    fgets is called much less frequently than read(), so the
    //    overhead of checking each line is acceptable.
    // ==================================================================
    try {
        var fgetsPtr = Module.findExportByName(null, "fgets");
        if (fgetsPtr) {
            Interceptor.attach(fgetsPtr, {
                onLeave: function (retval) {
                    try {
                        if (retval.isNull()) return;
                        var line = retval.readUtf8String();
                        if (!line || line.length < 5) return;

                        // Only check lines that look like /proc content
                        if (line.indexOf("frida") !== -1 ||
                            line.indexOf("gum-js-loop") !== -1 ||
                            line.indexOf("gmain") !== -1 ||
                            line.indexOf("linjector") !== -1 ||
                            line.indexOf("pool-frida") !== -1) {
                            // Replace with empty line
                            retval.writeUtf8String("\n");
                            return;
                        }

                        // Fix TracerPid
                        if (line.indexOf("TracerPid:") !== -1) {
                            var fixed = line.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
                            retval.writeUtf8String(fixed);
                            return;
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}

    // ==================================================================
    // 4. Hook close() - clean up fd tracking
    // ==================================================================
    try {
        var closePtr = Module.findExportByName(null, "close");
        if (closePtr) {
            Interceptor.attach(closePtr, {
                onEnter: function (args) {
                    try {
                        var fd = args[0].toInt32();
                        if (procFds[fd] !== undefined) {
                            delete procFds[fd];
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}

    // ==================================================================
    // 5. Hook connect() - block port 27042/27043 detection probes
    //    (Lightweight: only reads 4 bytes from sockaddr)
    // ==================================================================
    try {
        var connectPtr = Module.findExportByName(null, "connect");
        if (connectPtr) {
            Interceptor.attach(connectPtr, {
                onEnter: function (args) {
                    try {
                        var sockaddr = args[1];
                        var family = sockaddr.readU16();
                        if (family === 2) { // AF_INET
                            var port = (sockaddr.add(2).readU8() << 8) |
                                       sockaddr.add(3).readU8();
                            if (port === 27042 || port === 27043) {
                                args[2] = ptr(0);
                            }
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}

    console.log("[AntiFrida] Native anti-detection hooks installed (optimized)");
})();
