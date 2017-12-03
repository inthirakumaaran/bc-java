package org.bouncycastle.MYclass;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jsse.provider.ProvSSLSessionImpl;
import org.bouncycastle.jsse.provider.ProvSSLSocketFactory;
import org.bouncycastle.tls.TlsSessionImpl;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.io.Streams;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

import static org.bouncycastle.MYclass.Customsocket.check;
import static org.bouncycastle.MYclass.Customsocket.createSecContext;
import static org.bouncycastle.MYclass.Customsocket.getTokenbinding;
import static org.bouncycastle.MYclass.Customsocket.signatureMessage;

public class OnlySocket {
    static KeyPair keyPair;
    static KeyPair keyPair2;

    public static void main(String args[]) throws Exception {
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

//        SSLSocketFactory fact = clientContext.getSocketFactory();
        ProvSSLSocketFactory factt = (ProvSSLSocketFactory)clientContext.getSocketFactory();

        SSLSocket socket = (SSLSocket) factt.createSocket("wso2.is.com", 443);
//
        socket.startHandshake();

//        check(clientContext);
        NegotiatedTokenBinding negotiatedTokenBinding = getTokenbinding(clientContext);
        keyPair = crypto.createKeypair();
        keyPair2 = crypto.createKeypair();

//        String secTokenBinding=new String(Base64.encodeBase64URLSafe(createSecContext(negotiatedTokenBinding,0,
//                keyPair)));

        String secTokenBinding=new String(Base64.encodeBase64URLSafe(createTBMsg(keyPair,keyPair2,
                negotiatedTokenBinding)));

        String data1=URLEncoder.encode("grant_type", "UTF-8") + "=" + URLEncoder.encode("password", "UTF-8");
        String data2=URLEncoder.encode("username", "UTF-8") + "=" + URLEncoder.encode("admin", "UTF-8");
        String data3=URLEncoder.encode("password", "UTF-8") + "=" + URLEncoder.encode("admin", "UTF-8");
        String data4=URLEncoder.encode("client_id", "UTF-8") + "=" + URLEncoder.encode("6j9QcWJxGt10ffXxHwfmOTPrA3Aa", "UTF-8");
        String data5=URLEncoder.encode("client_secret", "UTF-8") + "=" + URLEncoder.encode("ustz8dmfn5fOADAgPU83wx1Wj0ca", "UTF-8");


        String data = data1+"&"+data2+"&"+data3+"&"+data4+"&"+data5;




        BufferedWriter wr = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF8"));
        wr.write("POST /oauth2/token  HTTP/1.1\r\n");
        wr.write("Content-Length: " + data.length() + "\r\n");
        wr.write("Content-Type: application/x-www-form-urlencoded\r\n");
        wr.write("Host: localhost \r\n");
        wr.write("Connection: keep-alive");
//            out.write("Agent: SSL-TEST\r\n");
//            out.write("Content-Type: application/x-www-form-urlencoded\r\n");
        wr.write("Cache-Control: no-cache\r\n");
        wr.write("Sec-token-binding: "+secTokenBinding+"\r\n");
        wr.write("\r\n");

        wr.write(data);
        wr.flush();

        byte[] buffer = new byte[1024];
        int read;
        InputStream is = socket.getInputStream();
        while((read = is.read(buffer)) != -1) {
            String output = new String(buffer, 0, read);
            System.out.print(output);
            System.out.flush();
        }
        socket.close();

    }

//    static void check(SSLContext sslContext) throws Exception {
//        Enumeration<byte[]> e = sslContext.getClientSessionContext().getIds();
//        while (e.hasMoreElements()) {
//            byte[] b = e.nextElement();
//            System.out.println("session id: " + DatatypeConverter.printHexBinary(b).toLowerCase());
//            ProvSSLSessionImpl Session = (ProvSSLSessionImpl) sslContext.getClientSessionContext().getSession(b);
//            TlsSessionImpl kumar = (TlsSessionImpl)Session.getTlsSession();
//            System.out.println(kumar.exportSessionParameters().getNegotiatedTokenBinding().getSelectedKeyParameter()
//                    +":"+kumar.exportSessionParameters().getNegotiatedTokenBinding().getExportKeyingMaterial());
//        }
//    }

    static byte[] createSecContext(NegotiatedTokenBinding negotiatedTokenBinding,int type,KeyPair keyPair) throws Exception{
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsUtils.writeUint8(type,buf);
        TlsUtils.writeUint8(0,buf);

        RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
        byte[] exponent=pub.getPublicExponent().toByteArray();
        byte[] modulus=pub.getModulus().toByteArray();

//        byte[] exponent=String.valueOf(pub.getPublicExponent().intValue()).getBytes();
//        byte[] modulus=String.valueOf(pub.getModulus().intValue()).getBytes();

//        System.out.println("exponent size is "+exponent.length);
//        System.out.println("modulus size is "+modulus.length);

        int keylength=exponent.length+modulus.length+3;
        TlsUtils.writeUint16(keylength,buf);
        TlsUtils.writeOpaque16(modulus,buf);
        TlsUtils.writeOpaque8(exponent,buf);
        TlsUtils.writeOpaque16(signatureMessage(negotiatedTokenBinding,keyPair,type),buf);
        TlsUtils.writeUint16(0,buf);
        TlsUtils.writeUint16(buf.size(),out);
        Streams.writeBufTo(buf, out);
        System.out.println("the message size is "+out.size());
        return out.toByteArray();
    }

    static byte[] signatureMessage(NegotiatedTokenBinding negotiatedTokenBinding,KeyPair keyPair,int type) throws
            Exception{
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeUint8(type,buf);
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

    static ByteArrayOutputStream createTokenBindingStructure(NegotiatedTokenBinding negotiatedTokenBinding,int type,KeyPair keyPair)
    throws Exception{
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsUtils.writeUint8(type,buf);
        TlsUtils.writeUint8(0,buf);

        RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
        byte[] exponent=pub.getPublicExponent().toByteArray();
        byte[] modulus=pub.getModulus().toByteArray();

//        byte[] exponent=String.valueOf(pub.getPublicExponent().intValue()).getBytes();
//        byte[] modulus=String.valueOf(pub.getModulus().intValue()).getBytes();

//        System.out.println("exponent size is "+exponent.length);
//        System.out.println("modulus size is "+modulus.length);

        int keylength=exponent.length+modulus.length+3;
        TlsUtils.writeUint16(keylength,buf);
        TlsUtils.writeOpaque16(modulus,buf);
        TlsUtils.writeOpaque8(exponent,buf);
        TlsUtils.writeOpaque16(signatureMessage(negotiatedTokenBinding,keyPair,type),buf);
        TlsUtils.writeUint16(0,buf);
//        TlsUtils.writeUint16(buf.size(),out);
//        Streams.writeBufTo(buf, out);
//        System.out.println("the message size is "+out.size());
        return buf;
    }

    static byte[] createTBMsg(KeyPair provided,KeyPair referred,NegotiatedTokenBinding negotiatedTokenBinding) throws Exception{
        ByteArrayOutputStream provideTB=createTokenBindingStructure(negotiatedTokenBinding,0,provided);
        ByteArrayOutputStream referredTB=createTokenBindingStructure(negotiatedTokenBinding,1,referred);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
//        byte[] TBMsg=concat(provideTB,referredTB);
//        ByteArrayOutputStream buf = new ByteArrayOutputStream(TBMsg.length);
//        buf.write(TBMsg, 0, TBMsg.length);
        TlsUtils.writeUint16(provideTB.size()+referredTB.size(),out);
        Streams.writeBufTo(provideTB, out);
        Streams.writeBufTo(referredTB, out);
        return out.toByteArray();

    }
}
