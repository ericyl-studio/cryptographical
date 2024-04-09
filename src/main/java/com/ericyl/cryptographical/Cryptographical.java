package com.ericyl.cryptographical;

public interface Cryptographical {

    byte[] encrypt(byte[] data);

    byte[] decrypt(byte[] data);

}
