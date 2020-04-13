package com.redteamobile.employee.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.ToString;
import lombok.experimental.Tolerate;

/**
 * @author Alex Liu
 * @date 2020/04/03
 */
@Builder
@ToString
public class OtaData {
    private String CID;
    private String MCC;
    private String ICCID;
    private String IMEI;
    private String localtime;
    private String MSISDN;
    private String writeCardResult;
    private String wroteICCID;

    public String getCID() {
        return this.CID;
    }

    @JsonProperty("CID")
    public void setCID(String CID) {
        this.CID = CID;
    }

    public String getMCC() {
        return this.MCC;
    }

    @JsonProperty("MCC")
    public void setMCC(String MCC) {
        this.MCC = MCC;
    }

    public String getICCID() {
        return this.ICCID;
    }

    @JsonProperty("ICCID")
    public void setICCID(String ICCID) {
        this.ICCID = ICCID;
    }

    public String getIMEI() {
        return this.IMEI;
    }

    @JsonProperty("IMEI")
    public void setIMEI(String IMEI) {
        this.IMEI = IMEI;
    }

    public String getLocaltime() {
        return this.localtime;
    }

    public void setLocaltime(String localtime) {
        this.localtime = localtime;
    }

    public String getMSISDN() {
        return this.MSISDN;
    }

    @JsonProperty("MSISDN")
    public void setMSISDN(String MSISDN) {
        this.MSISDN = MSISDN;
    }

    public String getWriteCardResult() {
        return this.writeCardResult;
    }

    public void setWriteCardResult(String writeCardResult) {
        this.writeCardResult = writeCardResult;
    }

    public String getWroteICCID() {
        return this.wroteICCID;
    }

    public void setWroteICCID(String wroteICCID) {
        this.wroteICCID = wroteICCID;
    }

    @Tolerate
    public OtaData(){}
}
