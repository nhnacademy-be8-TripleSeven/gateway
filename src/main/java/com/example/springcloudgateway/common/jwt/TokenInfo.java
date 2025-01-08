package com.example.springcloudgateway.common.jwt;

import lombok.*;

@Getter
@AllArgsConstructor
public class TokenInfo {
    private String grantType;
    private String accessToken;
    private String refreshToken;
}

