package com.ericyl.cryptographical.util;

import com.ericyl.cryptographical.properties.RSAModel;
import com.ericyl.cryptographical.rsa.RSACryptoImpl;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class RSAUtils {

    private static RSAPrivateKey privateKey;
    private static RSAPublicKey publicKey;
    private static X509Certificate caCert;

    static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_PADDING = "RSA/ECB/PKCS1Padding";
    private static final String SIGN_ALGORITHMS = "SHA1WithRSA";
//    private static final String COMMON_NAME = "";
//    private static final String ORGANIZATIONAL_UNIT = "";
//    private static final String ORGANIZATION = "";
//    private static final String CITY = "";
//    private static final String STATE = "";
//    private static final String COUNTRY = "";
//    private static final long VALIDITY = 100L * 365 * 24 * 60 * 60;

//    public static void createKey(RSAModel properties, int keySize, String privateKeyFileName, String publicKeyFileName) throws Exception {
//        Security.addProvider(new BouncyCastleProvider());
//
//        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
//
//        SecureRandom random = new SecureRandom(Base64.getDecoder().decode(properties.getSalt()));
//        if (keySize == 0)
//            keySize = 2048;
//        generator.initialize(keySize, random);
//        KeyPair keyPair = generator.generateKeyPair();
//
//        PrivateKey privateKey = keyPair.getPrivate();
//        PublicKey publicKey = keyPair.getPublic();
//
//        saveKey(publicKey.getEncoded(), publicKeyFileName);
//
//        X509Certificate[] chain = new X509Certificate[1];
//        X500Name x500Name = new X500Name(COMMON_NAME, ORGANIZATIONAL_UNIT, ORGANIZATION, CITY, STATE, COUNTRY);
//        chain[0] = getSelfCertificate(x500Name, x500Name, new Date(), VALIDITY, null, privateKey, publicKey);
//        saveToKeyStore(properties, privateKey, chain, privateKeyFileName);
//    }

    static void saveToKeyStore(RSAModel properties, PrivateKey key, X509Certificate[] chain, String fileName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);

        keyStore.setKeyEntry(properties.getKeyEntityAlias(), key, properties.getKeyEntityPwd().toCharArray(), chain);
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            keyStore.store(fos, properties.getKeyStorePwd().toCharArray());
        }


    }

    private static void saveKey(byte[] key, String fileName) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(key);
        }
    }

//    private static X509Certificate getSelfCertificate(X500Name var1, X500Name var100, Date var2, long var3, CertificateExtensions var5, PrivateKey privateKey, PublicKey publicKey) throws CertificateException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
//        try {
//            Security.addProvider(new BouncyCastleProvider());
//            Date var7 = new Date();
//            var7.setTime(var2.getTime() + var3 * 1000L);
//
//            CertificateValidity var8 = new CertificateValidity(var2, var7);
//            X509CertInfo var9 = new X509CertInfo();
//            var9.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
//            var9.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber((new Random()).nextInt() & 2147483647));
//            AlgorithmId var10 = AlgorithmId.get("SHA1withRSA");
//            var9.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(var10));
//            var9.set(X509CertInfo.SUBJECT, var100);
//            var9.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
//            var9.set(X509CertInfo.VALIDITY, var8);
//            var9.set(X509CertInfo.ISSUER, var1);
//            if (var5 != null)
//                var9.set(X509CertInfo.EXTENSIONS, var5);
//            X509CertImpl var6 = new X509CertImpl(var9);
//            var6.sign(privateKey, "SHA1withRSA");
//            return var6;
//        } catch (IOException var11) {
//            throw new CertificateEncodingException("getSelfCert: " + var11.getMessage());
//        }
//    }

    /**
     * 得到公钥
     */
    public static RSAPublicKey getPublicKey(InputStream is) throws Exception {
        if (null == publicKey) {
            synchronized (RSAPublicKey.class) {
                if (null == publicKey) {
                    KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);

                    try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                        byte[] buffer = new byte[4096];
                        int n;
                        while (-1 != (n = is.read(buffer))) {
                            output.write(buffer, 0, n);
                        }
                        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(output.toByteArray());
                        publicKey = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
                    }
                }
            }
        }
        return publicKey;

    }

    /**
     * 得到私钥
     */
    public static RSAPrivateKey getPrivateKey(RSAModel properties, InputStream is) throws Exception {
        if (null == privateKey) {
            synchronized (RSAPrivateKey.class) {
                if (null == privateKey) {
                    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                    keyStore.load(is, properties.getKeyStorePwd().toCharArray());
                    KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(properties.getKeyEntityAlias(), new KeyStore.PasswordProtection(properties.getKeyEntityPwd().toCharArray()));
                    privateKey = (RSAPrivateKey) entry.getPrivateKey();
                }
            }
        }
        return privateKey;

    }

    /**
     * 得到CA Cert
     */
    public static X509Certificate getCACert(RSAModel properties, InputStream is) throws Exception {
        if (null == caCert) {
            synchronized (RSAPrivateKey.class) {
                if (null == caCert) {
                    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                    keyStore.load(is, properties.getKeyStorePwd().toCharArray());
                    caCert = (X509Certificate) keyStore.getCertificate(properties.getKeyEntityAlias());
                }
            }
        }
        return caCert;

    }

    public static java.security.cert.Certificate[] getCert(RSAModel properties, InputStream is) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(is, properties.getKeyStorePwd().toCharArray());
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(properties.getKeyEntityAlias(), new KeyStore.PasswordProtection(properties.getKeyEntityPwd().toCharArray()));
        return keyStore.getCertificateChain(properties.getKeyEntityAlias());
    }

    /**
     * 加密
     */
    public static <T extends Key & RSAKey> String encrypt(T t, byte[] text) {
        return Base64.getEncoder().encodeToString(RSACryptoImpl.getInstance(t, RSA_PADDING).encrypt(text));
    }

    /**
     * 解密
     */
    public static <T extends Key & RSAKey> byte[] decrypt(T t, String text) {
        return RSACryptoImpl.getInstance(t, RSA_PADDING).decrypt(Base64.getDecoder().decode(text));
    }

    /**
     * 签名
     */
    public static String sign(RSAPrivateKey privateKey, String content) throws Exception {
        Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
        signature.initSign(privateKey);
        signature.update(content.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        return Base64.getEncoder().encodeToString(signed);
    }

    /**
     * 验证
     */
    public static boolean verify(RSAPublicKey publicKey, String content, String sign) throws Exception {
        Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
        signature.initVerify(publicKey);
        signature.update(content.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.getDecoder().decode(sign));
    }

    /**
     * 校验证书
     */
    public static boolean verifyCertificate(X509Certificate certificate, RSAPublicKey rsaPublicKey) {
        return verifyCertificate(new Date(), certificate, rsaPublicKey);
    }

    /**
     * 校验证书
     */
    private static boolean verifyCertificate(Date date, X509Certificate certificate, RSAPublicKey rsaPublicKey) {
        try {
            certificate.checkValidity(date);
            certificate.verify(rsaPublicKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


}