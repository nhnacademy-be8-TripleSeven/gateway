package com.example.springcloudgateway.common.jwt;

import com.example.springcloudgateway.common.error.jwt.TokenValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtProvider {

    @Value("${spring.profiles.active}")
    private String profile;

    private final static String AUTH_SERVICE_NAME = "auth-api";
    private final WebClient.Builder webClientBuilder;
    private final DiscoveryClient discoveryClient;

    /**
     * 리프레시 토큰을 사용하여 새로운 액세스 토큰을 발급받는 메서드
     */
    public Mono<TokenInfo> refreshAccessToken(String refreshToken, ServerWebExchange exchange) {
        String authServiceUrl = getAuthServiceUrl();

        WebClient webClient = webClientBuilder.baseUrl(authServiceUrl).build();

        return webClient.get()
                .uri("/auth/refresh/token")
                .header("refresh-token", refreshToken)
                .retrieve()
                .bodyToMono(TokenInfo.class)
                .doOnError(error -> log.error("Error refreshing token", error))
                .onErrorMap(ex -> new TokenValidationException("Error during token refresh", ex))
                .flatMap(tokenInfo -> addCookiesAndReturnTokenInfo(tokenInfo, exchange));
    }

    private String getAuthServiceUrl() {
        return discoveryClient.getInstances(AUTH_SERVICE_NAME)
                .stream()
                .findAny()
                .map(instance -> instance.getMetadata().get("domain"))
                .orElseThrow(() -> new RuntimeException("Auth service not found"));
    }

    private Mono<TokenInfo> addCookiesAndReturnTokenInfo(TokenInfo tokenInfo, ServerWebExchange exchange) {
        // 쿠키 추가
        addCookieToResponse(exchange, "jwt_token", tokenInfo.getAccessToken(), 60 * 60);
        addCookieToResponse(exchange, "refresh-token", tokenInfo.getRefreshToken(), 3 * 24 * 60 * 60);

        // 반환값 처리
        return Mono.just(tokenInfo);
    }

    private void addCookieToResponse(ServerWebExchange exchange, String cookieName, String cookieValue, int maxAge) {
        ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(cookieName, cookieValue)
                .httpOnly(true)
                .path("/")
                .maxAge(maxAge);

        if (!"dev".equals(profile)) {
            cookieBuilder.secure(true);
        }

        ResponseCookie cookie = cookieBuilder.build();
        exchange.getResponse().addCookie(cookie);
    }

    public String resolveRefreshToken(ServerWebExchange exchange) {
        HttpCookie refreshToken = exchange.getRequest().getCookies()
                .getFirst("refresh-token");

        if (refreshToken != null) {
            return refreshToken.getValue();
        }

        return null;
    }
}
