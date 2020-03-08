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

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkService.class);

    public void work() {
        LOGGER.info("TUTU JIAYOU");
    }

}
