package com.redteamobile.employee.model.excel;

import com.alibaba.excel.annotation.ExcelProperty;
import lombok.Builder;
import lombok.Data;
import lombok.experimental.Tolerate;

/**
 * 基础数据类
 *
 * @author Jiaju Zhuang
 **/
@Data
@Builder
public class EidExcel {
    @ExcelProperty("EID")
    private String string;

    @Tolerate
    public EidExcel(){}
}
