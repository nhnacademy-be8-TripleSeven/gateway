package com.example.springcloudgateway.common.filter;

import com.example.springcloudgateway.common.error.jwt.TokenValidationException;
import com.example.springcloudgateway.common.jwt.JwtValidator;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private final JwtValidator jwtValidator;

    public JwtAuthenticationFilter(JwtValidator jwtValidator) {
        super(Config.class);
        this.jwtValidator = jwtValidator;
    }

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {
            String token = jwtValidator.resolveToken(exchange);
            if (token != null && jwtValidator.validateToken(token)) {
                Authentication authentication = jwtValidator.getAuthentication(token);
                exchange = exchange.mutate()
                        .request(exchange.getRequest().mutate()
                                .header(config.getHeaderName(), authentication.getName())
                                .build())
                        .build();
            }
            return chain.filter(exchange);
        };
    }

    @Getter
    @Setter
    public static class Config {
        // 필터에서 사용할 설정 값들을 여기에 추가

        private String headerName;
    }
}
