package com.example.springcloudgateway.common.error;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDateTime;

@AllArgsConstructor
@Getter
public class ErrorMessage {

    private int statusCode;
    private LocalDateTime localDateTime;
    private String message;
    private String requestPath;
}
