# TrustMeAlready v2.8.0

![License](https://img.shields.io/github/license/cam3500/TrustMeAlready2)
![Downloads](https://img.shields.io/github/downloads/cam3500/TrustMeAlready2/total)

A comprehensive Android security bypass module combining **LSPosed** (Java layer) and **Frida** (Native/Framework layer) to bypass SSL pinning, VPN/proxy detection, developer options, debugger, emulator, user certificate, network security config, SafetyNet/Play Integrity, and anti-Frida detection.

**Dual-mode Frida integration**: automatically detects frida-server (port 27042) and switches between Gadget auto-injection (no server needed) and Frida-Server mode (interactive debugging).

Supports **Android 5.0 (API 21) through Android 16 (API 36)**.

## Architecture

```
???????????????????????????????????????????????????????????????
?                     TrustMeAlready v2.8.0                   ?
???????????????????????????????????????????????????????????????
?   LSPosed (Java?)    ?        Frida (Native/Framework?)     ?
???????????????????????????????????????????????????????????????
? SSLPinningBypass      ?  native_ssl_bypass.js                ?
? VPNBypass             ?  flutter_bypass.js                   ?
? ProxyBypass (disabled)?  react_native_bypass.js              ?
? DeveloperOptionsBypass?  cordova_bypass.js                   ?
? DebuggerBypass        ?  hybrid_framework_bypass.js           ?
? EmulatorBypass        ?  anti_frida_detection.js             ?
? UserCertificateBypass ?                                      ?
? NetworkSecurityBypass ?  FridaController (???):           ?
? SafetyNetBypass       ?    Mode A: frida-server (port 27042) ?
? AntiFridaBypass       ?    Mode B: frida-gadget (auto-inject) ?
???????????????????????????????????????????????????????????????
?         HookHelper (??Hook???)  ?  FridaController       ?
?         HookModule (????)        ?  (??????????)  ?
???????????????????????????????????????????????????????????????
?                    Main.java (?????)                     ?
???????????????????????????????????????????????????????????????
```

## LSPosed Bypass Modules (Java Layer)

| Module | Key Hook Points |
|--------|----------------|
| **SSLPinningBypass** | Conscrypt TrustManagerImpl, OpenSSLSocketImpl, CertPinManager, NetworkSecurityTrustManager, OkHttp CertificatePinner, HttpsURLConnection, SSLContext, TrustManagerFactory, Apache HttpClient, WebView, Cronet, TrustKit, WorkLight, Cordova, Netty, xUtils, CertificateTransparency |
| **VPNBypass** | NetworkCapabilities.hasTransport(VPN), NetworkInterface.getNetworkInterfaces, NetworkInterface.isUp/isVirtual, Runtime.exec(route inspection) |
| **ProxyBypass** | System.getProperty(proxy keys), ProxySelector.select, ConnectivityManager.getDefaultProxy |
| **DeveloperOptionsBypass** | Settings.Secure/Global.getInt/getString, ActivityManager.isRunningInTestHarness, SystemProperties.get, PackageManager.getPackageInfo (FLAG_DEBUGGABLE) |
| **DebuggerBypass** | Debug.isDebuggerConnected, Debug.waitForDebugger, Process.killProcess (anti-debug self-kill), System.exit/Runtime.exit (anti-suicide) |
| **EmulatorBypass** | ro.kernel.qemu detection (NO Build field spoofing - prevents account logout) |
| **UserCertificateBypass** | TrustManagerImpl.isUserAddedCertificate, TrustedCertificateStore, NetworkSecurityConfig user CA methods |
| **NetworkSecurityBypass** | NetworkSecurityConfig.isCleartextTrafficPermitted, NetworkSecurityPolicy, ConfigNetworkSecurityPolicy, ManifestConfigSource |
| **SafetyNetBypass** | SafetyNetClient.attest, AttestationResponse (JWS/status), IntegrityManager, IntegrityTokenResponse, StandardIntegrityManager/Token, GoogleApiAvailability |
| **AntiFridaBypass** | File.exists/canRead (frida paths), Runtime.exec (frida/su/ps/netstat), System.loadLibrary/load, PackageManager (frida packages), Socket.connect (port 27042/27043), BufferedReader.readLine (TracerPid, /proc/maps, /proc/net/tcp port 69A2) |

## Frida Scripts (Native/Framework Layer)

| Script | Coverage |
|--------|----------|
| **native_ssl_bypass.js** | BoringSSL (SSL_CTX_set_verify, SSL_set_verify, SSL_get_verify_result, SSL_CTX_set_custom_verify, X509_verify_cert), OpenSSL, generic module export scanning |
| **flutter_bypass.js** | Flutter engine BoringSSL, ssl_verify_peer_cert, ssl_crypto_x509_session_verify_cert_chain, libflutter.so export scanning, Java-layer supplement |
| **react_native_bypass.js** | Flipper interceptor, OkHttpClientProvider, CertificatePinner, RCTNetworking, Cronet native, TrustKit |
| **cordova_bypass.js** | CordovaWebViewClient, SystemWebViewClient, XWalkCordovaViewClient, Whitelist, SSLCertificateChecker, Ionic Native HTTP |
| **hybrid_framework_bypass.js** | Root detection (fopen/access/stat), Frida detection (fgets maps, pthread_setname_np, connect port check), Debug detection (ptrace, TracerPid), Emulator detection (__system_property_get), VPN/proxy detection |
| **anti_frida_detection.js** | Native-layer anti-Frida: open()/read() filtering (/proc/maps, /proc/status), opendir() (/proc/self/task), dlopen() hiding, strstr() blocking, pthread_getname_np, connect() port 27042/27043, dl_iterate_phdr |

## Build

### Prerequisites

- Android Studio (Hedgehog or newer)
- JDK 17+ (bundled with Android Studio)
- Android SDK with:
  - Platform android-34
  - Build Tools 34.0.0

### Build with Android Studio

1. Open the project in Android Studio
2. Wait for Gradle sync to complete
3. Build > Build Bundle(s) / APK(s) > Build APK(s)

### Build with Gradle

```bash
# Set JAVA_HOME if needed
export JAVA_HOME=/path/to/jdk

# Build debug APK
./gradlew assembleDebug

# Output: app/build/outputs/apk/debug/app-debug.apk
```

### Mirror Configuration

- **Gradle distribution**: Tencent Cloud mirror (Aliyun does not host all Gradle versions)
- **Maven repositories**: Aliyun mirrors (configured in `settings.gradle.kts`)

## Installation

### LSPosed Module

1. Install the APK on your device
2. Enable the module in LSPosed Manager
3. Select target apps in the scope
4. Restart the target apps

### Frida Integration (Dual-Mode: Gadget + Server)

The module features **dual-mode** Frida integration. FridaController automatically detects which mode to use at app startup:

#### Mode A: Frida-Server (Interactive Debugging)

When frida-server is running on the device (port 27042 in LISTEN state or process found), FridaController:
1. Extracts all Frida scripts to `/data/data/<package>/tma_frida_scripts/`
2. **Skips** gadget download/loading (frida-server and gadget CANNOT coexist)
3. Logs instructions for connecting via `frida -U`

**Setup:**

```bash
# 1. Download frida-server matching your device architecture
#    from https://github.com/frida/frida/releases

# 2. Push and start frida-server on device
adb push frida-server /data/local/tmp/
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"

# 3. Launch target app (LSPosed module auto-activates)
#    FridaController will detect frida-server and extract scripts

# 4. Connect from PC with all scripts
frida -U -f <package> \
  -l /data/data/<package>/tma_frida_scripts/native_ssl_bypass.js \
  -l /data/data/<package>/tma_frida_scripts/flutter_bypass.js \
  -l /data/data/<package>/tma_frida_scripts/react_native_bypass.js \
  -l /data/data/<package>/tma_frida_scripts/cordova_bypass.js \
  -l /data/data/<package>/tma_frida_scripts/hybrid_framework_bypass.js \
  -l /data/data/<package>/tma_frida_scripts/anti_frida_detection.js \
  --no-pause
```

**Advantages:** Interactive debugging, attach/detach at any time, load custom scripts on the fly.

#### Mode B: Frida-Gadget Auto-Injection (Zero Setup)

When frida-server is **NOT** running, FridaController automatically:
1. Detects CPU architecture (arm64/arm/x86/x86_64)
2. Downloads `frida-gadget-{version}-android-{arch}.so.xz` from GitHub
3. Decompresses using pure Java XZ library (org.tukaani:xz)
4. Loads gadget via `System.load()` (renamed to `libtma.so`)
5. Gadget auto-loads scripts from `tma_frida_scripts/` directory

**No setup required** - just install the APK, enable in LSPosed, and launch the target app. The gadget is downloaded once and cached for subsequent launches.

**Advantages:** Zero configuration, no PC connection needed, works standalone on device.

#### Anti-Frida Detection Bypass

Both modes are protected by AntiFridaBypass:
- **Java layer** (AntiFridaBypass.java): hides frida paths, blocks detection commands, filters /proc reads, blocks port 27042/27043 probes
- **Native layer** (anti_frida_detection.js): hooks open()/read()/connect()/strstr() to filter frida traces at the native level

The anti-detection hooks are applied **before** the gadget is loaded or before the app can detect frida-server, ensuring seamless operation.

## Project Structure

```
TrustMeAlready-master/
??? app/
?   ??? src/main/
?   ?   ??? java/mfsx/xposed/trustmealready/
?   ?   ?   ??? Main.java              # Module coordinator
?   ?   ?   ??? HookHelper.java        # Reflection hook utilities
?   ?   ?   ??? FridaController.java   # Dual-mode Frida injection (Gadget + Server)
?   ?   ?   ??? DummyTrustManager.java
?   ?   ?   ??? DummyHostnameVerifier.java
?   ?   ?   ??? DummySSLSocketFactory.java
?   ?   ?   ??? hooks/
?   ?   ?       ??? HookModule.java
?   ?   ?       ??? SSLPinningBypass.java
?   ?   ?       ??? VPNBypass.java
?   ?   ?       ??? ProxyBypass.java         # (disabled - conflicts with proxy capture)
?   ?   ?       ??? DeveloperOptionsBypass.java
?   ?   ?       ??? DebuggerBypass.java
?   ?   ?       ??? EmulatorBypass.java
?   ?   ?       ??? UserCertificateBypass.java
?   ?   ?       ??? NetworkSecurityBypass.java
?   ?   ?       ??? SafetyNetBypass.java
?   ?   ?       ??? AntiFridaBypass.java     # Java-layer anti-Frida detection
?   ?   ??? assets/
?   ?   ?   ??? xposed_init
?   ?   ?   ??? frida/
?   ?   ?   ?   ??? native_ssl_bypass.js
?   ?   ?   ?   ??? flutter_bypass.js
?   ?   ?   ?   ??? react_native_bypass.js
?   ?   ?   ?   ??? cordova_bypass.js
?   ?   ?   ?   ??? hybrid_framework_bypass.js
?   ?   ?   ?   ??? anti_frida_detection.js  # Native-layer anti-Frida
?   ?   ?   ??? frida-gadget/
?   ?   ?       ??? config.json              # Gadget interaction config
?   ?   ??? res/values/strings.xml
?   ?   ??? AndroidManifest.xml
?   ??? build.gradle.kts
??? settings.gradle.kts
??? build.gradle.kts
??? gradle/wrapper/gradle-wrapper.properties
??? gradle.properties
```

## Project Coverage Scenarios

### TLS/SSL Coverage

| TLS Version | Support | Mechanism |
|-------------|---------|-----------|
| TLS 1.0 | Full | SSLContext.getInstance() ? "TLS", setEnabledProtocols() ? getSupportedProtocols() |
| TLS 1.1 | Full | Same as above |
| TLS 1.2 | Full | Same as above + setSSLParameters() re-enable |
| TLS 1.3 | Full | Same as above (system-supported) |

### App Type Coverage

| App Type | Coverage Layer | Details |
|----------|---------------|---------|
| Native Android (Java/Kotlin) | LSPosed Java | All 9 bypass modules active |
| Flutter/Dart | Frida Native | flutter_bypass.js hooks BoringSSL in libflutter.so |
| React Native | LSPosed + Frida | Java-layer OkHttp/Cronet + react_native_bypass.js |
| Cordova/Ionic | LSPosed + Frida | Java-layer WebView + cordova_bypass.js |
| Hybrid (WebView) | LSPosed + Frida | WebView SSL error + hybrid_framework_bypass.js |
| Custom Native (C/C++) | Frida Native | native_ssl_bypass.js hooks BoringSSL/OpenSSL exports |

### Detection Bypass Coverage

| Detection Category | Bypass Modules | Key Techniques |
|-------------------|---------------|----------------|
| SSL Certificate Pinning | SSLPinningBypass | Conscrypt, OkHttp, WebView, Cronet, TrustKit, Netty, xUtils, +20 frameworks |
| TLS Protocol Restriction | SSLPinningBypass (TLS) | Force-enable all supported TLS versions (1.0-1.3) |
| VPN Detection | VPNBypass | NetworkCapabilities, NetworkInterface, route inspection |
| Proxy Detection | ProxyBypass (disabled) | System properties, ProxySelector, ConnectivityManager |
| Developer Options/ADB | DeveloperOptionsBypass | Settings.Secure/Global, isRunningInTestHarness, FLAG_DEBUGGABLE |
| Debugger Detection | DebuggerBypass | isDebuggerConnected, anti-suicide (System.exit/Runtime.exit/killProcess) |
| Emulator Detection | EmulatorBypass | ro.kernel.qemu (no Build spoofing to avoid account logout) |
| User Certificate | UserCertificateBypass | isUserAddedCertificate, TrustedCertificateStore |
| Network Security Config | NetworkSecurityBypass | isCleartextTrafficPermitted, NetworkSecurityPolicy |
| SafetyNet/Play Integrity | SafetyNetBypass | SafetyNetClient.attest, IntegrityManager, GoogleApiAvailability |
| Anti-Frida Detection | AntiFridaBypass + anti_frida_detection.js | Java + Native dual-layer: file/process/port/maps hiding |

### Architecture Coverage

| Architecture | Frida-Gadget | Frida-Server |
|-------------|-------------|-------------|
| arm64-v8a | libtma.so (auto-download) | Supported |
| armeabi-v7a | libtma.so (auto-download) | Supported |
| x86 | libtma.so (auto-download) | Supported |
| x86_64 | libtma.so (auto-download) | Supported |

### Android Version Coverage

| Android Version | API Level | Status |
|----------------|-----------|--------|
| Android 5.0 | 21 | Supported |
| Android 5.1 | 22 | Supported |
| Android 6.0 | 23 | Supported |
| Android 7.0-7.1 | 24-25 | Supported |
| Android 8.0-8.1 | 26-27 | Supported |
| Android 9 | 28 | Supported |
| Android 10 | 29 | Supported |
| Android 11 | 30 | Supported |
| Android 12 | 31-32 | Supported |
| Android 13 | 33 | Supported |
| Android 14 | 34 | Supported |
| Android 15 | 35 | Supported |
| Android 16 | 36 | Supported (caution) |

## License

See [LICENSE](LICENSE).
