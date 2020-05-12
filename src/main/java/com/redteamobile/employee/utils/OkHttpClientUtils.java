package com.redteamobile.employee.utils;

import okhttp3.OkHttpClient;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;

/**
 * @author Alex Liu
 * @date 2020/04/26
 */
public class OkHttpClientUtils {

    // TLS/SSLv3
    private static final String PROTOCOL = "TLS";		//SSLv3

    // JKS/PKCS12
    private static final String KEY_KEYSTORE_TYPE = "JCEKS";

    private static final String SUN_X_509 = "SunX509";

    private static SSLContext getSslContext(KeyManager[] keyManagers, TrustManager[] trustManagers) throws Exception{
        SSLContext sslContext = SSLContext.getInstance(PROTOCOL);
        sslContext.init(keyManagers, trustManagers, new SecureRandom());
        return sslContext;
    }

    private static KeyManager[] getKeyManagers(InputStream keystore, String password)throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(SUN_X_509);
        KeyStore keyStore = KeyStore.getInstance(KEY_KEYSTORE_TYPE);
        keyStore.load(keystore, password.toCharArray());
        keyManagerFactory.init(keyStore, password.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
        return keyManagers;
    }

    private static TrustManager[] getTrustManagers(InputStream keystore, String password)throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(SUN_X_509);
        KeyStore keyStore = KeyStore.getInstance(KEY_KEYSTORE_TYPE);
        keyStore.load(keystore, password.toCharArray());
        trustManagerFactory.init(keyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        return trustManagers;
    }

    public static OkHttpClient get() throws Exception{

        // 客户端证书的路径
        String keystorePath1 = "src/main/resources/client_test.jks";
        String keystorePath2 = "src/main/resources/BipKeystore2.jks";

        // keystore的密码
        String keystorePassword1 = "123456";
        String keystorePassword2 = "654321";

        KeyManager[] keyManagers = getKeyManagers(Files.newInputStream(Paths.get(keystorePath1)),keystorePassword1);
        TrustManager[] trustManagers = getTrustManagers(Files.newInputStream(Paths.get(keystorePath2)),keystorePassword2);
        SSLContext sslContext = getSslContext(keyManagers,trustManagers);

        return new OkHttpClient.Builder().sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustManagers[0])
                .hostnameVerifier((host,sslSession) -> {
                    // 校验证书域名
                    return true;
                }).build();
    }
}
