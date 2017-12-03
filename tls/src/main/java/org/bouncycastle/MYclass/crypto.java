package org.bouncycastle.MYclass;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.ASN1Dump;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

public class crypto {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(keyPair.getPrivate());

        System.out.println(keyPair.getPrivate());
        System.out.println(keyPair.getPublic());

        RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();

        BigInteger expo = pub.getPublicExponent();

        System.out.println();

        byte[] message = "abc".getBytes();
        signature.update(message);

        byte[] sigBytes = signature.sign();
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());

        byte[] decSig = cipher.doFinal(sigBytes);
        ASN1InputStream aIn = new ASN1InputStream(decSig);
        ASN1Sequence seq = (ASN1Sequence) aIn.readObject();

        System.out.println(ASN1Dump.dumpAsString(seq));

        MessageDigest hash = MessageDigest.getInstance("SHA-256", "BC");
        hash.update(message);

        ASN1OctetString sigHash = (ASN1OctetString) seq.getObjectAt(1);
        System.out.println(MessageDigest.isEqual(hash.digest(), sigHash.getOctets()));
    }

    public static KeyPair createKeypair() throws NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();

    }

    public static byte[] signMessage(byte[] message,KeyPair keyPair) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(keyPair.getPrivate());
        signature.update(message);
        return signature.sign();
    }

//    public static byte[] createTokenBindingID(int tBtype,KeyPair keyPair){
//
//
//    }
 }


