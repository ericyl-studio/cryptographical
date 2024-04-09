package com.ericyl.cryptographical.properties;

public class CertProperties {

    private String commonName;
    private String organizationalUnit;
    private String organization;

    public CertProperties(String commonName, String organizationalUnit, String organization) {
        this.commonName = commonName;
        this.organizationalUnit = organizationalUnit;
        this.organization = organization;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getOrganizationalUnit() {
        return organizationalUnit;
    }

    public void setOrganizationalUnit(String organizationalUnit) {
        this.organizationalUnit = organizationalUnit;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }
}
