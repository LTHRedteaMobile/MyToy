package com.redteamobile.employee.service;

import com.redteamobile.employee.model.req.FIFOReq;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author Alex Liu
 * @date 2020/02/19
 */
@Service
@EnableAsync
public class FIFOService {

    private static final Logger LOGGER = LoggerFactory.getLogger(FIFOService.class);

    private Map<Integer, ExecutorService> threadPoolMap = new HashMap<>(24);

    private Map<Integer, ReentrantLock> lockMap = new HashMap<>();

    @Autowired
    private WorkService workService;

    @PostConstruct
    public void initial(){
        for(int i = 0 ; i < 24 ; i++){
            threadPoolMap.put( i , Executors.newSingleThreadExecutor());
        }

        for(int i = 0 ; i < 24 ; i++){
            lockMap.put( i , new ReentrantLock(true));
        }
    }

    @Async("SingleThreadPool")
    public void testFIFO(FIFOReq fifoReq) throws Exception{
        Task task = new Task(fifoReq);
        getThreadPool(fifoReq.getClientId()).submit(task);
        /*ReentrantLock lock = getLock(fifoReq.getClientId());
        lock.lock();
        workService.work(fifoReq);*/
    }


    class Task implements Runnable{

        private FIFOReq fifoReq;

        public Task(FIFOReq fifoReq){
            this.fifoReq = fifoReq;
        }

        @Override
        public void run(){
            LOGGER.info(fifoReq.toString());
        }
    }

    private ExecutorService getThreadPool(String id){
        return threadPoolMap.get(id.hashCode()%24);
    }

    private ReentrantLock getLock(String id){
        return lockMap.get(id.hashCode()%24);
    }


}
