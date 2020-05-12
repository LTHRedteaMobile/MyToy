package com.redteamobile.employee.model.mongo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.event.AuditingEventListener;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;
import javax.persistence.EntityListeners;


/**
 * @author Alex Liu
 * @date 2020/04/30
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
//@EntityListeners(AuditingEventListener.class)
public class User implements Serializable {

    @Id
    private BigInteger id;
    private String name;
    @Indexed
    private Integer age;
    private Date createdDate;
    private Date updateDate;

    public User(String name, Integer age, Date createdDate, Date updateDate){
        this.name = name;
        this.age = age;
        this.createdDate = createdDate;
        this.updateDate = updateDate;
    }

}
