package com.redteamobile.employee.model.req;

import lombok.Builder;
import lombok.Data;
import lombok.experimental.Tolerate;

/**
 * @author Alex Liu
 * @date 2020/04/27
 */
@Data
@Builder
public class Header {
    private String s1;
    private String s2;

    @Tolerate
    public Header(){}
}
