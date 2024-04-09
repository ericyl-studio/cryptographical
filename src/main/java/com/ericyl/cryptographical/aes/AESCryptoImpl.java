package com.ericyl.cryptographical.aes;

import com.ericyl.cryptographical.Cryptographical;
import com.ericyl.cryptographical.exception.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

public class AESCryptoImpl implements Cryptographical {
    
    private final Cipher cipher;
    private final SecretKeySpec key;
    private final IvParameterSpec iv;

    private AESCryptoImpl(String algorithm, SecretKeySpec key, byte[] iv) {
        this.key = key;
        this.iv = new IvParameterSpec(iv);
        Security.addProvider(new BouncyCastleProvider());
        try {
            this.cipher = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }


    public static AESCryptoImpl getInstance(SecretKeySpec keySpec, String algorithm, byte[] iv) {
        return new AESCryptoImpl(algorithm, keySpec, iv);
    }

    public static AESCryptoImpl getInstance(byte[] key, String algorithm, byte[] iv) {
        return getInstance(com.ericyl.cryptographical.aes.AESCryptoKey.getInstance(key).getKey(), algorithm, iv);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        try {
            return doFinal(Cipher.ENCRYPT_MODE, data);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) {
        try {
            return doFinal(Cipher.DECRYPT_MODE, data);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    private byte[] doFinal(int opmode, byte[] input) throws Exception {
        cipher.init(opmode, key, iv);
        return cipher.doFinal(input);
    }

}
