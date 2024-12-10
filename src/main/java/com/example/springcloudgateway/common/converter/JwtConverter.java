package com.example.springcloudgateway.common.converter;

import com.example.springcloudgateway.common.jwt.JwtValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Component
@Slf4j
public class JwtConverter implements ServerAuthenticationConverter {

    private final JwtValidator jwtValidator;

    public JwtConverter(JwtValidator jwtValidator) {
        this.jwtValidator = jwtValidator;
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        String token = jwtValidator.resolveToken(exchange.getRequest());
        try {
            if(!Objects.isNull(token) && jwtValidator.validateToken(token)){
                return Mono.justOrEmpty(jwtValidator.getAuthentication(token));
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return Mono.empty();
    }
}
