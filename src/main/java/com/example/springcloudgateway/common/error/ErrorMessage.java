package com.example.springcloudgateway.common.error;

import lombok.AllArgsConstructor;

import java.time.LocalDateTime;

@AllArgsConstructor
public class ErrorMessage {

    private int statusCode;
    private LocalDateTime localDateTime;
    private String message;
    private String requestPath;
}
