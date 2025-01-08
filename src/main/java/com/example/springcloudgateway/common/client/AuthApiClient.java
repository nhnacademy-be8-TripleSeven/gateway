package com.example.springcloudgateway.common.client;

import com.example.springcloudgateway.common.jwt.TokenInfo;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import reactor.core.publisher.Mono;

@FeignClient(name = "auth-api")
public interface AuthApiClient {

    @GetMapping("/auth/refresh/token")
    Mono<TokenInfo> reIssueAccessToken(@RequestHeader("refresh-token") String refreshToken);
}
