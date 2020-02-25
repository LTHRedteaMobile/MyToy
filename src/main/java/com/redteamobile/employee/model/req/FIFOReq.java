package com.redteamobile.employee.model.req;

import lombok.Builder;
import lombok.Data;
import lombok.experimental.Tolerate;

/**
 * @author Alex Liu
 * @date 2020/02/19
 */
@Data
@Builder
public class FIFOReq {
    private String clientId;
    private String seqId;

    @Tolerate
    public FIFOReq(){}
}
