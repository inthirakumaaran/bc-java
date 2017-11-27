package org.bouncycastle.MYclass;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URI;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Basic SSL Client - using the '!' protocol.
 */
public class Testclient
{
    public static void main(
            String[] args)
            throws Exception
    {

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleJsseProvider());
        }

        TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
                BouncyCastleJsseProvider.PROVIDER_NAME);

        KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX",
                BouncyCastleJsseProvider.PROVIDER_NAME);

        KeyStore ks = KeyStore.getInstance("JKS");

        ks.load(new FileInputStream("keystore.jks"), "123456".toCharArray());

        keyMgrFact.init(ks, "123456".toCharArray());

        trustMgrFact.init(ks);

        SSLContext clientContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);

        clientContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(),
                SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));

        SSLSocketFactory fact = clientContext.getSocketFactory();

        String urlParameters = "grant_type=password&username=admin&password=admin&client_id=fVP9QwdYOqZGhJWAlNFsr6M1QvIa" +
                "&client_secret=TC5IJTSm6gbfp6AC8hTGgC3iDqca";
        byte[] postData = urlParameters.getBytes("UTF-8");
        int postDataLength = postData.length;

//        URI uri = new URI(
//                "https",
//                "localhost:9444",
//                "/oauth2/token",
//                null);
//        URL url = uri.toURL();
//        System.out.println(url);
//        String request        = "https://wso2.is.com//oauth2/token";

        String request = "https://localhost:9444//oauth2/token";

        URL url = new URL(request);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(fact);
        conn.setDoOutput(true);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("charset", "utf-8");
        conn.setRequestProperty("Content-Length", Integer.toString(postDataLength));
        conn.setUseCaches(false);
        DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
        wr.write(postData);
        InputStream is;
        if (conn.getResponseCode() >= 400) {
            is = conn.getErrorStream();
        } else {
            is = conn.getInputStream();
        }
        Reader in = new BufferedReader(new InputStreamReader(is, "UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (int c; (c = in.read()) >= 0; )
            sb.append((char) c);
        String response = sb.toString();
        System.out.println(response);


    }




}