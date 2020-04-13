package com.redteamobile.employee.model;

import lombok.Builder;
import lombok.Data;
import lombok.experimental.Tolerate;

/**
 * @author Alex Liu
 * @date 2020/04/03
 */
@Data
@Builder
public class OtaDataToCms {
    private int requestType;
    private String cid;
    private OtaData data;

    @Tolerate
    public OtaDataToCms(){}
}
