package com.ericyl.cryptographical.util;

import com.ericyl.cryptographical.aes.AESCryptoImpl;
import com.ericyl.cryptographical.exception.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

public class AESUtils {
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_PADDING = "AES/CBC/PKCS7PADDING";

    public static SecretKey createKey(int keySize) {
        Security.addProvider(new BouncyCastleProvider());

        KeyGenerator generator;
        try {
            generator = KeyGenerator.getInstance(AES_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception e) {
            throw new CryptoException(e);
        }

        if (keySize == 0)
            keySize = 256;
        generator.init(keySize, new SecureRandom());
        return generator.generateKey();
    }

    public static String encrypt(SecretKey secretKey, String originalText, byte[] iv) {
        return Base64.getEncoder().encodeToString(AESCryptoImpl.getInstance(secretKey.getEncoded(), AES_PADDING, iv).encrypt(originalText.getBytes(StandardCharsets.UTF_8)));
    }

    public static String encrypt(byte[] secretKey, String originalText, byte[] iv) {
        return Base64.getEncoder().encodeToString(AESCryptoImpl.getInstance(secretKey, AES_PADDING, iv).encrypt(originalText.getBytes(StandardCharsets.UTF_8)));
    }

    public static String decrypt(SecretKey secretKey, String cipherText, byte[] iv) {
        return new String(AESCryptoImpl.getInstance(secretKey.getEncoded(), AES_PADDING, iv).decrypt(Base64.getDecoder().decode(cipherText)), StandardCharsets.UTF_8);
    }

    public static String decrypt(byte[] secretKey, String cipherText, byte[] iv) {
        return new String(AESCryptoImpl.getInstance(secretKey, AES_PADDING, iv).decrypt(Base64.getDecoder().decode(cipherText)), StandardCharsets.UTF_8);
    }

    public static String getIv(int size) {
        if (size == 0)
            size = 16;
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

}
