package com.redteamobile.employee.service;

import feign.Response;
import feign.codec.ErrorDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Alex Liu
 * @date 2020/04/27
 */
public class CustomErrorDecoder implements ErrorDecoder {
    private static final Logger LOGGER = LoggerFactory.getLogger(CustomErrorDecoder.class);
    @Override
    public Exception decode(String methodKey, Response response) {

        switch (response.status()){
            case 400:
                LOGGER.error("400");
                return new Exception();
            case 404:
                LOGGER.error("400");
                return new Exception();
            default:
                return new Exception("Generic error");
        }
    }
}
