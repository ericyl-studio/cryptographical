package com.ericyl.cryptographical.properties;


public class RSAModel {
    private String keyStorePwd;
    private String keyEntityAlias;
    private String keyEntityPwd;
    private String salt;

    public RSAModel() {
    }

    public RSAModel(String keyStorePwd, String keyEntityAlias, String keyEntityPwd, String salt) {
        this.keyStorePwd = keyStorePwd;
        this.keyEntityAlias = keyEntityAlias;
        this.keyEntityPwd = keyEntityPwd;
        this.salt = salt;
    }

    public String getKeyStorePwd() {
        return keyStorePwd;
    }

    public void setKeyStorePwd(String keyStorePwd) {
        this.keyStorePwd = keyStorePwd;
    }

    public String getKeyEntityAlias() {
        return keyEntityAlias;
    }

    public void setKeyEntityAlias(String keyEntityAlias) {
        this.keyEntityAlias = keyEntityAlias;
    }

    public String getKeyEntityPwd() {
        return keyEntityPwd;
    }

    public void setKeyEntityPwd(String keyEntityPwd) {
        this.keyEntityPwd = keyEntityPwd;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
