package com.redteamobile.employee.service;

import com.redteamobile.employee.model.req.FIFOReq;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author Alex Liu
 * @date 2020/02/20
 */
@Service
public class WorkService {

    private static final Logger LOGGER = LoggerFactory.getLogger(FIFOService.class);


    @Async("ThreadPool1")
    public void work(FIFOReq fifoReq , ReentrantLock lock) throws Exception{
        try {
            lock.lock();
            LOGGER.info(fifoReq.toString());
        }catch (Exception e){
            LOGGER.error("do nothing");
        }finally {
            LOGGER.info(fifoReq.toString() + "解锁");
            lock.unlock();

        }
    }

}
