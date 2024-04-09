package com.ericyl.cryptographical.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Utils {
    private static final char[] DIGITS_LOWER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static String md5ToHex(String source) throws NoSuchAlgorithmException {
        byte[] data = MessageDigest.getInstance("MD5").digest(source.getBytes(StandardCharsets.UTF_8));

        final int l = data.length;
        final char[] out = new char[l << 1];
        encodeHex(data, 0, data.length, DIGITS_LOWER, out, 0);
        return new String(out);
    }

    private static void encodeHex(final byte[] data, final int dataOffset, final int dataLen, final char[] toDigits,
                                  final char[] out, final int outOffset) {
        // two characters form the hex value.
        for (int i = dataOffset, j = outOffset; i < dataOffset + dataLen; i++) {
            out[j++] = toDigits[(0xF0 & data[i]) >>> 4];
            out[j++] = toDigits[0x0F & data[i]];
        }
    }
}
