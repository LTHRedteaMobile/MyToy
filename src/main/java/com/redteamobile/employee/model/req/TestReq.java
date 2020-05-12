package com.redteamobile.employee.model.req;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import lombok.experimental.Tolerate;

/**
 * @author Alex Liu
 * @date 2020/04/26
 */

@Data
@SuperBuilder
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class TestReq extends BaseReq{
    private String mnoid;
    private String mnoName;
    private String mnoAddress;

    @Tolerate
    public TestReq(){}
}
