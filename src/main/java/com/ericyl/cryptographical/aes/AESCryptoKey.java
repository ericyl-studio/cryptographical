package com.ericyl.cryptographical.aes;


import com.ericyl.cryptographical.CryptoKeyable;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESCryptoKey implements CryptoKeyable<SecretKeySpec> {

    private final byte[] data;

    private AESCryptoKey(byte[] data) {
        this.data = data;
    }

    public static AESCryptoKey getInstance(byte[] data) {
        return new AESCryptoKey(data);
    }

    public static AESCryptoKey getInstance(SecretKey secretKey) {
        return getInstance(secretKey.getEncoded());
    }


    @Override
    public SecretKeySpec getKey() {
        return new SecretKeySpec(data, "AES");
    }
}
