package mfsx.xposed.trustmealready;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class DummyTrustManager implements X509TrustManager {
    private static TrustManager[] trustManagers = null;

    public static TrustManager[] getInstance() {
        if (trustManagers == null) {
            trustManagers = new TrustManager[1];
            trustManagers[0] = new DummyTrustManager();
        }
        return trustManagers;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    @SuppressWarnings("unused")
    public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType, String host) {
        // Return the original chain so that downstream consumers (SSL session
        // peer certificates, OkHttp CertificateChainCleaner, Conscrypt CT/OCSP)
        // have the certificate info they need. Returning an empty list caused
        // WeChat mini program image loading to fail because the SSL session
        // had no peer certificate chain.
        List<X509Certificate> list = new ArrayList<>();
        if (chain != null) {
            for (X509Certificate cert : chain) {
                if (cert != null) list.add(cert);
            }
        }
        return list;
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}