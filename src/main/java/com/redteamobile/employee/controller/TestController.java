package com.redteamobile.employee.controller;

import com.redteamobile.employee.async.AsyncTask;
import com.redteamobile.employee.model.mongo.Admin;
import com.redteamobile.employee.model.mongo.AdminRepository;
import com.redteamobile.employee.model.req.FIFOReq;
import com.redteamobile.employee.model.req.TestReq;
import com.redteamobile.employee.service.FIFOService;
import com.redteamobile.employee.service.MongoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.List;

/**
 * @author Alex Liu
 * @date 2020/02/19
 */

@RestController
@RequestMapping("/test")
public class TestController {

    @Autowired
    private FIFOService fifoService;
    @Autowired
    private AsyncTask asyncTask;
    @Autowired
    private MongoTemplate mongoTemplate;
    @Autowired
    private MongoService mongoService;
    @Autowired
    private AdminRepository adminRepository;

    //private Executor executor = Executors.newSingleThreadExecutor();

    @ResponseBody
    @RequestMapping(value = "/FIFO" , method = RequestMethod.GET)
    public void testFIFO() throws Exception{
        for(int i = 1 ; i <= 5 ; i++){
            for(int j = 1 ; j <= 5 ; j++){
                /*FIFOReq fifoReq = FIFOReq.builder().clientId(i+"").seqId(j+"").build();
                System.out.println(fifoReq.getClientId().hashCode());*/
                fifoService.testFIFO(FIFOReq.builder().clientId(i+"").seqId(j+"").build());
            }
        }

    }

    @ResponseBody
    @RequestMapping(value = "/test" , method = RequestMethod.POST)
    public void test(@RequestBody TestReq testReq) throws Exception{
        System.out.println(testReq);
        testReq.getHeader();
        //SSLClient.build("https://nusim-dp-qa.redtea.io/test").test2(TestReq.builder().mnoid("1").mnoName("test").build());
        System.out.println("111");
    }

    @ResponseBody
    @RequestMapping(value = "/insert" , method = RequestMethod.GET)
    public void insert(){
        /*User user1 = User.builder().age(10).name("pingguo").build();*/
        Admin admin1 = Admin.builder().level("223").name("admin").age(10).createdDate(new Date()).updateDate(new Date()).build();
        Admin admin2 = Admin.builder().level("223").name("admin").age(40).createdDate(new Date()).updateDate(new Date()).build();
        Admin admin3 = Admin.builder().level("223").name("admin").age(30).createdDate(new Date()).updateDate(new Date()).build();
        //mongoService.insert(user1);
        //mongoService.insert(admin);
        adminRepository.save(admin1);
        adminRepository.save(admin2);

        adminRepository.save(admin3);

        /*mongoTemplate.insert(user1, "Users");
        mongoTemplate.insert(user2 , "Users");*/

    }



    @ResponseBody
    @RequestMapping(value = "/get" , method = RequestMethod.GET)
    public void get(){
        List<Admin> admins = adminRepository.findAllByAgeBefore(40);
        System.out.println(admins);


        Pageable pageable = PageRequest.of(0, 3, Sort.Direction.DESC, "age");

        Page<Admin> admin1 = adminRepository.findAllByLevelContainingAndCreatedDateAfter("223",new Date(),pageable);
        System.out.println(admin1.getContent().size());
        Page<Admin> admin2 = adminRepository.findAllByLevelContainingAndCreatedDateBefore("223",new Date(),pageable);
        System.out.println(admin2.getContent().size());
        System.out.println(admin2.getContent().get(0));
        System.out.println(admin2.getContent().get(1));
        System.out.println(admin2.getContent().get(2));

    }

    private void edit(){

    }

}

