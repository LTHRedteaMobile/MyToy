package com.redteamobile.employee.model.excel;

import com.alibaba.excel.annotation.ExcelProperty;
import lombok.Builder;
import lombok.Data;
import lombok.experimental.Tolerate;

/**
 * @author Alex Liu
 * @date 2020/03/31
 */
@Data
@Builder
public class ProfileExcel {
    @ExcelProperty("ICCID")
    private String iccid;
    @ExcelProperty("IMSI")
    private String imsi;
    @ExcelProperty("KI")
    private String ki;
    @ExcelProperty("OPC")
    private String opc;

    @Tolerate
    public ProfileExcel(){}
}
