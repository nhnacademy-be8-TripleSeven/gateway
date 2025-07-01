package com.example.springcloudgateway.common.config;


import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteConfig {

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("object-storage-proxy", r -> r.path("/storage/**")
                        .filters(f -> f.stripPrefix(1)) // /storage 제거
                        .uri("http://storage.java21.net:8000"))
                .build();
    }
}