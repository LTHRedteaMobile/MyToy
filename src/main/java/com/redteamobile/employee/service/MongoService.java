package com.redteamobile.employee.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Service;

/**
 * @author Alex Liu
 * @date 2020/05/09
 */
@Service
public class MongoService {

    @Autowired
    private MongoTemplate mongoTemplate;

    public <T> void insert(T object){
        System.out.println(object);
        System.out.println(object.getClass().getSimpleName());
        mongoTemplate.insert(object , object.getClass().getSimpleName());
    }
}
