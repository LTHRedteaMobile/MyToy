package com.redteamobile.employee.model.mongo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.Tolerate;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.event.AuditingEventListener;

import javax.persistence.EntityListeners;
import java.util.Date;


/**
 * @author Alex Liu
 * @date 2020/05/09
 */
@Data
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@Document(collection = "admin_collection")
public class Admin extends User{
    private String level;


    @Builder
    public Admin(String name, Integer age, String level, Date createdDate, Date updateDate){
        super(name, age, createdDate, updateDate);
        this.level = level;
    }


}
