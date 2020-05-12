package com.redteamobile.employee.model.mongo;

import org.apache.catalina.LifecycleState;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.repository.Repository;

import java.util.Date;
import java.util.List;

/**
 * @author Alex Liu
 * @date 2020/05/11
 */
public interface AdminRepository extends Repository<Admin, Long> {

    Admin save(Admin admin);

    Admin findAllByLevel(String level);

    List<Admin> findAllByAgeBefore(Integer age);

    //Admin findAllByLevelOrderByAge

    Page<Admin> findAllByLevelContaining(String level, Pageable pageable);

    Page<Admin> findAllByLevelContainingAndCreatedDateAfter(String level, Date date,Pageable pageable);

    Page<Admin> findAllByLevelContainingAndCreatedDateBefore(String level, Date date,Pageable pageable);


}
