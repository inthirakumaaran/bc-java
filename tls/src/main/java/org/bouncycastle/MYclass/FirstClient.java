package org.bouncycastle.MYclass;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jsse.provider.*;
import org.bouncycastle.tls.TlsSession;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;

public class FirstClient {
    public static void main(String[] args) throws Exception
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

        String data ="IkAAgBBQKzyIrmcY_YCtHVoSHBut69vrGfFdy1_YKTZfFJv6BjrZsKD9b9FRzSBxDs1twTqnAS71M1RBumui" +
                "hhI9xqxXKkAQEtxe4jeUJU0WezxlQXWVSBFeHxFMdXRBIH_LKOSAuSMOJ0XEw1Q8DE248qkOiRKzw3Kd" +
                "SNYukYEPmO21bQi3YYAAA";

        String urlParameters  = "grant_type=password&username=admin&password=admin&client_id=fVP9QwdYOqZGhJWAlNFsr6M1QvIa&client_secret=TC5IJTSm6gbfp6AC8hTGgC3iDqca";
        byte[] postData       = urlParameters.getBytes("UTF-8" );
        int    postDataLength = postData.length;
//        URI uri = new URI(
//                "https",
//                "localhost",
//                "//oauth2/token",
//                null);
//        String request = uri.toASCIIString();
//        URL url = uri.toURL();
        String request        = "https://localhost:9444/oauth2/token";
        URL url            = new URL( request);
        HttpsURLConnection conn= (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(fact);
        conn.setDoOutput( true );
        conn.setInstanceFollowRedirects( false );
        conn.setRequestMethod( "POST" );
        conn.setRequestProperty( "token-binding", data);
        conn.setRequestProperty( "Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty( "charset", "utf-8");
        conn.setRequestProperty( "Content-Length", Integer.toString( postDataLength ));
        conn.setUseCaches( false );

        DataOutputStream wr = new DataOutputStream( conn.getOutputStream());
        wr.write( postData );
        System.out.println(clientContext.getClientSessionContext());
        InputStream is;
        if (conn.getResponseCode() >= 400) {
            is = conn.getErrorStream();
        } else {
            is = conn.getInputStream();
        }
        Reader in = new BufferedReader(new InputStreamReader(is, "UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (int c; (c = in.read()) >= 0;)
            sb.append((char)c);
        String response = sb.toString();
        System.out.println(response);

    }

    protected static X509TrustManager findX509TrustManager(TrustManager[] tms)
    {
        if (tms != null)
        {
            for (TrustManager tm : tms)
            {
                if (tm instanceof X509TrustManager)
                {
                    return (X509TrustManager)tm;
                }
            }
        }
        return null;
    }

}
