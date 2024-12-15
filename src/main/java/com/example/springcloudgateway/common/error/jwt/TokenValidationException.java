package com.example.springcloudgateway.common.error.jwt;

import org.springframework.security.core.AuthenticationException;

public class TokenValidationException extends AuthenticationException {
    public TokenValidationException(String message) {
        super(message);
    }

    public TokenValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}