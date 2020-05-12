package com.redteamobile.employee.client;

import com.redteamobile.employee.model.req.TestReq;
import com.redteamobile.employee.model.res.TestRes;
import com.redteamobile.employee.service.CustomErrorDecoder;
import com.redteamobile.employee.utils.OkHttpClientUtils;
import feign.Feign;
import feign.Headers;
import feign.Logger;
import feign.RequestLine;
import feign.Retryer;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.okhttp.OkHttpClient;
import feign.slf4j.Slf4jLogger;
import org.apache.logging.slf4j.SLF4JLogger;
import org.slf4j.LoggerFactory;

/**
 * @author Alex Liu
 * @date 2020/04/26
 */
public interface SSLClient {
    final org.slf4j.Logger logger = LoggerFactory.getLogger(SSLClient.class);

    @Headers({"Content-Type: application/json"})
    @RequestLine("POST")
    @jdk.nashorn.internal.runtime.logging.Logger
    void test2(TestReq req);

    static SSLClient build(String url) throws Exception{
        Feign.Builder builder =
                Feign.builder().client(new OkHttpClient(OkHttpClientUtils.get())).logger(new Logger.JavaLogger()).logger(new Slf4jLogger())
                        .logLevel(Logger.Level.FULL).errorDecoder(new CustomErrorDecoder()).decode404()
                        .retryer(new Retryer.Default()).encoder(new GsonEncoder()).decoder(new GsonDecoder());

        return builder.target(SSLClient.class, url);
    }

}
