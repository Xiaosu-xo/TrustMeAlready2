package mfsx.xposed.trustmealready.hooks;

import android.util.Base64;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import mfsx.xposed.trustmealready.HookHelper;

/**
 * Bypasses Google SafetyNet Attestation and Play Integrity API checks
 * by intercepting attestation/token response methods to return fake
 * passing results, and ensuring GoogleApiAvailability reports success.
 */
public class SafetyNetBypass implements HookModule {

    // Fake JWS payload indicating a passing attestation
    private static final String FAKE_JWS_HEADER =
            "{\"typ\":\"JWT\",\"alg\":\"RS256\"}";
    private static final String FAKE_JWS_PAYLOAD =
            "{\"nonce\":\"-\",\"timestampMs\":0,\"apkPackageName\":\"-\","
                    + "\"apkCertificateDigestSha256\":[\"-\"],"
                    + "\"apkDigestSha256\":\"-\","
                    + "\"ctsProfileMatch\":true,"
                    + "\"basicIntegrity\":true,"
                    + "\"evaluationType\":\"BASIC\"}";

    // Fake integrity token (long base64-like string)
    private static final String FAKE_INTEGRITY_TOKEN =
            "CAEQ5dgBEokBeyJwcm90ZWN0ZWRQYXlsb2FkIjoiZXlKcmFXUWlPaU"
                    + "pwYzI5MFpXUWlMQ0poY0d0RWJtc2lNelV3TWpVMklpd2lZV1J"
                    + "FSWlpaUlpd2ljSFZpYkdsalgyUmxiaUlzSW1sa0lqb2lOV0ky"
                    + "TkRrNU5EWWlMQ0pqYjI1MFpYaDBJam9pWVRJek5EWTBZek0wT"
                    + "0RJM01qQTNOR0kwT1RJNU1qZzBZV1UzWVRZM01qTTBOelUyWk"
                    + "RrNE9HTTRaVGN5TnpJMk1UUTNOemt4T1RreE1EazJNREEzTWp"
                    + "Fek9ESTJOVGd4T1RjM05qY3lOVEV5TlRBMU1UTTNNR0prWmpr"
                    + "MU1UYzNPRGcyTmpRMU16a3hOVGd5TURBPV9zaWduYXR1cmVfc"
                    + "GxhY2Vob2xkZXIifQ";

    @Override
    public String name() {
        return "SafetyNet / Play Integrity Bypass";
    }

    @Override
    public void apply(HookHelper h) {
        hookSafetyNetClientAttest(h);
        hookSafetyNetAttestationResponse(h);
        hookIntegrityManagerRequestToken(h);
        hookIntegrityTokenResponse(h);
        hookStandardIntegrityManagerPrepare(h);
        hookStandardIntegrityToken(h);
        hookStandardIntegrityTokenProvider(h);
        hookIntegrityServiceException(h);
        hookGoogleApiAvailability(h);
    }

    // ------------------------------------------------------------------
    // SafetyNetClient.attest - let proceed (no-op hook)
    // ------------------------------------------------------------------
    private void hookSafetyNetClientAttest(HookHelper h) {
        try {
            h.hookMethodsWithCallback(
                    "com.google.android.gms.safetynet.SafetyNetClient",
                    new XC_MethodHook() {
                        // Let the method proceed normally; the bypass
                        // happens in the response hooks below.
                    }, "attest");
        } catch (Throwable t) {
            h.logError("SafetyNetClient.attest", t);
        }
    }

    // ------------------------------------------------------------------
    // SafetyNetApi$AttestationResponse - fake JWS and success status
    // ------------------------------------------------------------------
    private void hookSafetyNetAttestationResponse(HookHelper h) {
        final String className = "com.google.android.gms.safetynet.SafetyNetApi$AttestationResponse";

        // getJwsResult ? fake passing JWS
        try {
            h.hookMethodsWithCallback(className,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(buildFakeJws());
                        }
                    }, "getJwsResult");
        } catch (Throwable t) {
            h.logError("SafetyNetApi$AttestationResponse.getJwsResult", t);
        }

        // getStatus ? Status(0) SUCCESS
        try {
            h.hookMethodsWithCallback(className,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                Class<?> statusClass = h.findClass(
                                        "com.google.android.gms.common.api.Status");
                                if (statusClass != null) {
                                    Object successStatus = XposedHelpers.newInstance(
                                            statusClass, 0);
                                    param.setResult(successStatus);
                                }
                            } catch (Throwable ignored) {
                                // leave original on failure
                            }
                        }
                    }, "getStatus");
        } catch (Throwable t) {
            h.logError("SafetyNetApi$AttestationResponse.getStatus", t);
        }
    }

    // ------------------------------------------------------------------
    // IntegrityManager.requestIntegrityToken - let proceed
    // ------------------------------------------------------------------
    private void hookIntegrityManagerRequestToken(HookHelper h) {
        try {
            h.hookMethodsWithCallback(
                    "com.google.android.play.core.integrity.IntegrityManager",
                    new XC_MethodHook() {
                        // Let proceed; bypass via token response hook.
                    }, "requestIntegrityToken");
        } catch (Throwable t) {
            h.logError("IntegrityManager.requestIntegrityToken", t);
        }
    }

    // ------------------------------------------------------------------
    // IntegrityTokenResponse.token ? fake token
    // ------------------------------------------------------------------
    private void hookIntegrityTokenResponse(HookHelper h) {
        try {
            h.hookMethodsWithCallback(
                    "com.google.android.play.core.integrity.IntegrityTokenResponse",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(FAKE_INTEGRITY_TOKEN);
                        }
                    }, "token");
        } catch (Throwable t) {
            h.logError("IntegrityTokenResponse.token", t);
        }

        // Also hook method name pattern used in some versions
        try {
            h.hookMethodsWithCallback(
                    "com.google.android.play.core.integrity.IntegrityTokenResponse",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(FAKE_INTEGRITY_TOKEN);
                        }
                    }, "getTokens");
        } catch (Throwable t) {
            h.logError("IntegrityTokenResponse.getTokens", t);
        }
    }

    // ------------------------------------------------------------------
    // StandardIntegrityManager.prepareIntegrityToken - let proceed
    // ------------------------------------------------------------------
    private void hookStandardIntegrityManagerPrepare(HookHelper h) {
        try {
            h.hookMethodsWithCallback(
                    "com.google.android.play.core.integrity.StandardIntegrityManager",
                    new XC_MethodHook() {
                        // Let proceed; bypass via token hook.
                    }, "prepareIntegrityToken");
        } catch (Throwable t) {
            h.logError("StandardIntegrityManager.prepareIntegrityToken", t);
        }
    }

    // ------------------------------------------------------------------
    // StandardIntegrityToken.token ? fake token
    // ------------------------------------------------------------------
    private void hookStandardIntegrityToken(HookHelper h) {
        try {
            h.hookMethodsWithCallback(
                    "com.google.android.play.core.integrity.StandardIntegrityToken",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(FAKE_INTEGRITY_TOKEN);
                        }
                    }, "token");
        } catch (Throwable t) {
            h.logError("StandardIntegrityToken.token", t);
        }
    }

    // ------------------------------------------------------------------
    // StandardIntegrityTokenProvider.request - let proceed
    // ------------------------------------------------------------------
    private void hookStandardIntegrityTokenProvider(HookHelper h) {
        try {
            h.hookMethodsWithCallback(
                    "com.google.android.play.core.integrity.StandardIntegrityTokenProvider",
                    new XC_MethodHook() {
                        // Let proceed; bypass via token hook.
                    }, "request");
        } catch (Throwable t) {
            h.logError("StandardIntegrityTokenProvider.request", t);
        }
    }

    // ------------------------------------------------------------------
    // IntegrityServiceException.getErrorCode ? 0
    // ------------------------------------------------------------------
    private void hookIntegrityServiceException(HookHelper h) {
        try {
            h.hookMethodsReturnConstant(
                    "com.google.android.play.core.integrity.IntegrityServiceException", 0,
                    "getErrorCode");
        } catch (Throwable t) {
            h.logError("IntegrityServiceException.getErrorCode", t);
        }

        // Also hook getStatusCode for completeness
        try {
            h.hookMethodsReturnConstant(
                    "com.google.android.play.core.integrity.IntegrityServiceException", 0,
                    "getStatusCode");
        } catch (Throwable t) {
            h.logError("IntegrityServiceException.getStatusCode", t);
        }
    }

    // ------------------------------------------------------------------
    // GoogleApiAvailability.isGooglePlayServicesAvailable ? 0 (SUCCESS)
    // ------------------------------------------------------------------
    private void hookGoogleApiAvailability(HookHelper h) {
        try {
            h.hookMethodsReturnConstant(
                    "com.google.android.gms.common.GoogleApiAvailability", 0,
                    "isGooglePlayServicesAvailable");
        } catch (Throwable t) {
            h.logError("GoogleApiAvailability.isGooglePlayServicesAvailable", t);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    private static String buildFakeJws() {
        String headerB64 = Base64.encodeToString(FAKE_JWS_HEADER.getBytes(),
                Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        String payloadB64 = Base64.encodeToString(FAKE_JWS_PAYLOAD.getBytes(),
                Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        return headerB64 + "." + payloadB64 + ".fake-signature";
    }
}
