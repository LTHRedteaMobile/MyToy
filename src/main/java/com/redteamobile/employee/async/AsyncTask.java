package com.redteamobile.employee.async;

import com.redteamobile.employee.service.WorkService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * @author Alex Liu
 * @date 2020/03/08
 */
@Component
public class AsyncTask {
    private static final Logger logger = LoggerFactory.getLogger(AsyncTask.class);

    @Autowired
    private WorkService workService;

    @Async("ThreadPool1")
    public void work(){
        workService.work();
    }
}
