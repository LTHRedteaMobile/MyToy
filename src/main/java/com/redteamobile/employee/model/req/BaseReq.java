package com.redteamobile.employee.model.req;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import lombok.experimental.Tolerate;

/**
 * @author Alex Liu
 * @date 2020/04/27
 */

@Data
@SuperBuilder
@AllArgsConstructor
public class BaseReq {
    private Header header;

    @Tolerate
    public BaseReq(){}
}
