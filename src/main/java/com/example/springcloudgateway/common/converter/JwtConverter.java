package com.example.springcloudgateway.common.converter;

import com.example.springcloudgateway.common.error.jwt.TokenValidationException;
import com.example.springcloudgateway.common.jwt.JwtProvider;
import com.example.springcloudgateway.common.jwt.JwtValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtConverter implements ServerAuthenticationConverter {

    private final JwtValidator jwtValidator;
    private final JwtProvider jwtProvider;

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        String token = jwtValidator.resolveToken(exchange);

        if (Objects.isNull(token)) {
            return Mono.empty();
        }

        try {
            if (jwtValidator.validateToken(token)) {
                // 유효한 토큰인 경우 Authentication 반환
                return Mono.justOrEmpty(jwtValidator.getAuthentication(token));
            }
        } catch (TokenValidationException e) {
            log.warn("Token validation failed: {}", e.getMessage());

            // 토큰 만료 처리
            if (e.getMessage().contains("TOKEN_EXPIRED")) {
                String refreshToken = jwtProvider.resolveRefreshToken(exchange);
                return jwtProvider.refreshAccessToken(refreshToken, exchange)
                        .flatMap(tokenInfo -> {
                            Authentication authentication = jwtValidator.getAuthentication(tokenInfo.getAccessToken());
                            if (authentication == null) return Mono.empty();

                            exchange.getResponse().getHeaders().add("X-New-Token", tokenInfo.getAccessToken());

                            return Mono.just(authentication);
                        })
                        .onErrorResume(ex -> {
                            log.error("Failed to refresh access token: {}", ex.getMessage());
                            return Mono.empty();
                        });
            }
        } catch (Exception ex) {
            log.error("Unexpected error during token validation", ex);
        }

        // 인증 실패 또는 토큰이 유효하지 않은 경우 빈 Authentication 반환
        return Mono.empty();
    }
}
