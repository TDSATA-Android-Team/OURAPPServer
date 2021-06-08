package com.tdsata.ourappserver;

import com.tdsata.ourappserver.util.Server;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Timer;
import java.util.TimerTask;

@SpringBootApplication
public class OurappServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(OurappServerApplication.class, args);
        // RSA密钥对初始化以及每10分钟更新一次RSA密钥对
        new Timer().schedule(new TimerTask() {
            @Override
            public void run() {
                Server.generateRSAKeyPair();
            }
        }, 0, 600000/*10分钟*/);
    }
}
