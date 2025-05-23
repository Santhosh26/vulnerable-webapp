package com.example.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class VulnerableWebApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(VulnerableWebApplication.class, args);
    }
}