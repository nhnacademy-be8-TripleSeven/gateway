package com.example.springcloudgateway.common.filter;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@Slf4j
public class GuestIdFilter extends AbstractGatewayFilterFactory<GuestIdFilter.Config> {

    public GuestIdFilter() {
        super(GuestIdFilter.Config.class);
    }

    @Override
    public GatewayFilter apply(GuestIdFilter.Config config) {

        return (exchange, chain) -> {
            HttpCookie guestIdCookie = exchange.getRequest().getCookies().getFirst(config.cookieName);

            if (guestIdCookie != null && !guestIdCookie.getValue().isEmpty()) {
                // GUEST-ID 쿠키가 존재하는 경우

                String guestId = guestIdCookie.getValue();
                ResponseCookie responseCookie = ResponseCookie.from(config.cookieName, guestId)
                        .path("/") // 쿠키 경로 설정
                        .httpOnly(true) // HTTP 전용 쿠키
                        .maxAge(3 * 24 * 60 * 60)
                        .build();

                exchange.getResponse().addCookie(responseCookie);

            } else {
                String defaultGuestId = UUID.randomUUID().toString();
                ResponseCookie responseCookie = ResponseCookie.from(config.cookieName, defaultGuestId)
                        .path("/") // 쿠키 경로 설정
                        .httpOnly(true) // HTTP 전용 쿠키
                        .maxAge(3 * 24 * 60 * 60)
                        .build();

                exchange.getResponse().addCookie(responseCookie);
            }

            return chain.filter(exchange);
        };
    }

    @Getter
    @Setter
    public static class Config {
        // 필터에서 사용할 설정 값들을 여기에 추가

        private String cookieName;
    }
}
