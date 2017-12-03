package org.bouncycastle.MYclass;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpConnection;
import org.apache.commons.httpclient.HttpConnectionManager;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.protocol.Protocol;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jsse.provider.ProvSSLSessionContext;
import org.bouncycastle.jsse.provider.ProvSSLSessionImpl;
import org.bouncycastle.jsse.provider.ProvSSLSocketFactory;
import org.bouncycastle.tls.TlsSessionImpl;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.io.Streams;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

public class Customsocket {
    static KeyPair keyPair;


    public static void main(String[] args) throws Exception {

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

        ProvSSLSocketFactory fact = (ProvSSLSocketFactory)clientContext.getSocketFactory();



        HttpClient httpClient = new HttpClient();
        Protocol easyhttps = new Protocol("https", fact, 443);
        Protocol.registerProtocol("https", easyhttps);



        HostConfiguration hostconfig = new HostConfiguration();
        hostconfig.setHost("https://localhost/oauth2/token");


//        hostconfig.getParams().setParameter("http.protocol.version", HttpVersion.HTTP_1_0);

        String data ="AIkAAgBBQAs9SMs3dyk8K1cf9YxVKr-2drUou0HMPfpmuGleinZ1633Nc825dJNXXzjSrni-cjvxZZmDKIeyzHRjqmiLY2gAQJ7aMz57fS4Ky-JUC1QpRc7NGr9gM3IWIdHgEukfIPIXeYicOjxJvK4KMKVNEXLEwWlnz8xbl0nt2u4ZHCOAITAAAA";
//        GetMethod method = new GetMethod("https://localhost/oauth2/token");

//        keyPair = crypto.createKeypair();

//        HttpConnection httpConnection = new HttpConnection("https://localhost/oauth2/token",443,easyhttps);
//
//        httpConnection.open();
//        httpClient.executeMethod(method);
//        check(clientContext);
//        method.releaseConnection();
//
//        httpClient.executeMethod(method);
//        check(clientContext);
//        method.releaseConnection();

////        httpConnection.close();
//        httpClient.executeMethod(method);
//        System.out.println("hi");
//        check(clientContext);
//        method.releaseConnection();


//        PostMethod post = new PostMethod("https://localhost/oauth2/token");
        PostMethod post = new PostMethod("/");
        httpClient.executeMethod(hostconfig,post);
        check(clientContext);
        System.out.println("hi");
        NegotiatedTokenBinding negotiatedTokenBinding = getTokenbinding(clientContext);
        post.releaseConnection();

//        HttpPost post = new HttpPost(
//                "https://localhost:9444/oauth2/token");
//        clientContext.getClientSessionContext();
        String secTokenBinding=new String(Base64.encodeBase64URLSafe(createSecContext(negotiatedTokenBinding)));
        try {
            post.addRequestHeader("sec-token-binding",secTokenBinding);
//            post.addRequestHeader("summa",grepp(clientContext));
            post.addParameter("client_id", "fVP9QwdYOqZGhJWAlNFsr6M1QvIa");
            post.addParameter("client_secret", "TC5IJTSm6gbfp6AC8hTGgC3iDqca");
//            post.addParameter("sec-token-binding","jjjhhhhhddddd");
            post.addParameter("grant_type", "password");

            post.addParameter("username", "admin");
            post.addParameter("password", "admin");
            post.addParameter("redirect_uri", "http://localhost:10080/password/callback.php");
            httpClient.executeMethod(hostconfig,post);

            System.out.println(post.getResponseBodyAsString());
            check(clientContext);

            post.releaseConnection();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static void check(SSLContext sslContext) throws Exception {
        Enumeration<byte[]> e = sslContext.getClientSessionContext().getIds();
        while (e.hasMoreElements()) {
            byte[] b = e.nextElement();
            System.out.println("session id: " + DatatypeConverter.printHexBinary(b).toLowerCase());
            ProvSSLSessionImpl Session = (ProvSSLSessionImpl) sslContext.getClientSessionContext().getSession(b);
            TlsSessionImpl kumar = (TlsSessionImpl)Session.getTlsSession();
            System.out.println(kumar.exportSessionParameters().getNegotiatedTokenBinding().getSelectedKeyParameter()
                    +":"+kumar.exportSessionParameters().getNegotiatedTokenBinding().getExportKeyingMaterial());
        }
    }

    static String grepp(SSLContext sslContext) throws Exception {
        Enumeration<byte[]> e = sslContext.getClientSessionContext().getIds();
        String s="";
        while (e.hasMoreElements()) {
            byte[] b = e.nextElement();
            System.out.println("session id: " + DatatypeConverter.printHexBinary(b).toLowerCase());
            ProvSSLSessionImpl Session = (ProvSSLSessionImpl) sslContext.getClientSessionContext().getSession(b);
            TlsSessionImpl kumar = (TlsSessionImpl)Session.getTlsSession();
            s=kumar.exportSessionParameters().getNegotiatedTokenBinding().getSelectedKeyParameter()
                    +":"+new String(kumar.exportSessionParameters().getNegotiatedTokenBinding()
                    .getExportKeyingMaterial());
        }
        return s;
    }

    static NegotiatedTokenBinding getTokenbinding(SSLContext sslContext) throws Exception {
        Enumeration<byte[]> e = sslContext.getClientSessionContext().getIds();
        NegotiatedTokenBinding s= null;
        while (e.hasMoreElements()) {
            byte[] b = e.nextElement();
            System.out.println("session id: " + DatatypeConverter.printHexBinary(b).toLowerCase());
            ProvSSLSessionImpl Session = (ProvSSLSessionImpl) sslContext.getClientSessionContext().getSession(b);
            TlsSessionImpl kumar = (TlsSessionImpl)Session.getTlsSession();
            s=kumar.exportSessionParameters().getNegotiatedTokenBinding();
        }
        return s;
    }
    static byte[] createSecContext(NegotiatedTokenBinding negotiatedTokenBinding) throws Exception{
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsUtils.writeUint8(0,buf);
        TlsUtils.writeUint8(0,buf);

        RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
        byte[] exponent=pub.getPublicExponent().toByteArray();
        byte[] modulus=pub.getModulus().toByteArray();

//        byte[] exponent=String.valueOf(pub.getPublicExponent().intValue()).getBytes();
//        byte[] modulus=String.valueOf(pub.getModulus().intValue()).getBytes();

        System.out.println("exponent size is "+exponent.length);
        System.out.println("modulus size is "+modulus.length);

        int keylength=exponent.length+modulus.length+3;
        TlsUtils.writeUint16(keylength,buf);
        TlsUtils.writeOpaque16(modulus,buf);
        TlsUtils.writeOpaque8(exponent,buf);
        TlsUtils.writeOpaque16(signatureMessage(negotiatedTokenBinding),buf);
        TlsUtils.writeUint16(0,buf);
        TlsUtils.writeUint16(buf.size(),out);
        Streams.writeBufTo(buf, out);
        System.out.println("the message size is "+out.size());
        return out.toByteArray();
    }

    static byte[] signatureMessage(NegotiatedTokenBinding negotiatedTokenBinding) throws Exception{
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeUint8(0,buf);
        TlsUtils.writeUint8(0,buf);
        return crypto.signMessage(concat(buf.toByteArray(),negotiatedTokenBinding.exportKeyingMaterial),keyPair);
    }

    static byte[] concat(byte[] a, byte[] b)
    {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }




}


