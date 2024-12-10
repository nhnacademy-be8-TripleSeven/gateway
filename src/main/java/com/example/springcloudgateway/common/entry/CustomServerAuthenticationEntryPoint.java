package com.example.springcloudgateway.common.entry;

import com.example.springcloudgateway.common.error.ErrorMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Component
@Slf4j
public class CustomServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {
    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {

        String requestPath = exchange.getRequest().getPath().value();
        log.error("Unauthorized error: {}", ex.getMessage());
        log.error("Requested path    : {}", requestPath);
        ServerHttpResponse serverHttpResponse = exchange.getResponse();
        serverHttpResponse.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        serverHttpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);

        ErrorMessage errorMessage = new ErrorMessage(HttpStatus.UNAUTHORIZED.value()
                , LocalDateTime.now()
                , ex.getMessage()
                , requestPath);

        try {
            byte[] errorByte = new ObjectMapper()
                    .registerModule(new JavaTimeModule())
                    .writeValueAsBytes(errorMessage); // 나중에 직렬화, 역직렬화 설정 하기.
            DataBuffer dataBuffer = serverHttpResponse.bufferFactory().wrap(errorByte);
            return serverHttpResponse.writeWith(Mono.just(dataBuffer));
        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
            return serverHttpResponse.setComplete();
        }
    }
}
