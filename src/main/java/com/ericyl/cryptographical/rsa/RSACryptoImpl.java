package com.ericyl.cryptographical.rsa;

import com.ericyl.cryptographical.Cryptographical;
import com.ericyl.cryptographical.exception.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.Security;
import java.security.interfaces.RSAKey;

public class RSACryptoImpl<T extends Key & RSAKey> implements Cryptographical {


    private final Cipher cipher;
    private final T key;

    private RSACryptoImpl(String algorithm, T key) {
        this.key = key;
        Security.addProvider(new BouncyCastleProvider());
        try {
            this.cipher = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    public static <T extends Key & RSAKey> RSACryptoImpl getInstance(T key, String algorithm) {
        return new RSACryptoImpl<>(algorithm, key);
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
        cipher.init(opmode, key);
        return rsaSplitCodec(cipher, opmode, input, key.getModulus().bitLength());
    }

    private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize) {
        int maxBlock = 0;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            if (opmode == Cipher.DECRYPT_MODE) {
                maxBlock = keySize / 8;
            } else {
                maxBlock = keySize / 8 - 11;
            }
            int offSet = 0;
            byte[] buff;
            int i = 0;
            while (datas.length > offSet) {
                if (datas.length - offSet > maxBlock) {
                    buff = cipher.doFinal(datas, offSet, maxBlock);
                } else {
                    buff = cipher.doFinal(datas, offSet, datas.length - offSet);
                }
                out.write(buff, 0, buff.length);
                i++;
                offSet = i * maxBlock;
            }
            return out.toByteArray();
        } catch (Exception e) {
            throw new CryptoException("加解密阀值为[" + maxBlock + "]的数据时发生异常", e);
        }
    }

}
