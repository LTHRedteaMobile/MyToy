package com.redteamobile.employee.model.res;

import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import lombok.experimental.Tolerate;

/**
 * @author Alex Liu
 * @date 2020/04/26
 */
@Data
@Builder
public class TestRes {
    private String string;

    @Tolerate
    public TestRes(){}
}
