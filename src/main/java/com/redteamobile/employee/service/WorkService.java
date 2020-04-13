package com.redteamobile.employee.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

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
