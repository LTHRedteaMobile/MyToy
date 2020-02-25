package com.redteamobile.employee.controller;

import com.redteamobile.employee.model.req.FIFOReq;
import com.redteamobile.employee.service.FIFOService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * @author Alex Liu
 * @date 2020/02/19
 */

@RestController
@RequestMapping("/test")
public class TestController {

    @Autowired
    private FIFOService fifoService;

    private Executor executor = Executors.newSingleThreadExecutor();

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

    class TransferTask implements Runnable{

        private FIFOReq fifoReq;

        @Override
        public void run() {

        }
    }
}
