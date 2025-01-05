package com.example.springcloudgateway.common.config;

import com.example.springcloudgateway.common.converter.JwtConverter;
import com.example.springcloudgateway.common.entry.CustomServerAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.util.Arrays;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final JwtConverter jwtConverter;
    private final CustomServerAuthenticationEntryPoint customServerAuthenticationEntryPoint;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(csrfSpec -> csrfSpec.disable())
                .formLogin(formLogin -> formLogin.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .httpBasic(httpBasic -> httpBasic.disable())
                .logout(logout -> logout.disable())
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance()) // session STATELESS
                .exceptionHandling(exhandler -> exhandler.authenticationEntryPoint(customServerAuthenticationEntryPoint))
                .authorizeExchange(authorizeExchangeSpec -> {
                    authorizeExchangeSpec.pathMatchers("/members/**").permitAll();
                    authorizeExchangeSpec.pathMatchers("/cart/**").permitAll();
                    authorizeExchangeSpec.pathMatchers("/auth/**").permitAll();
                    authorizeExchangeSpec.pathMatchers("/frontend/**").permitAll();
                    authorizeExchangeSpec.pathMatchers("/api/**").hasRole("USER");
                    authorizeExchangeSpec.pathMatchers("/admin/**").hasRole("ADMIN");
                })
                .addFilterAt(authenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    private AuthenticationWebFilter authenticationWebFilter() {
        ReactiveAuthenticationManager authenticationManager = reactiveAuthenticationManager();
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(authenticationManager);
        authenticationWebFilter.setServerAuthenticationConverter(jwtConverter);
        authenticationWebFilter.setAuthenticationFailureHandler((webFilterExchange, exception) -> {
            return customServerAuthenticationEntryPoint.commence(webFilterExchange.getExchange(), exception);
        });
        return authenticationWebFilter;
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        return authentication -> {
            if (authentication.isAuthenticated()) {
                return Mono.just(authentication);
            }
            return Mono.error(new AuthenticationException("Invalid authentication") {});
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("https://nhn24.store"); // 허용할 Origin
        config.addAllowedMethod("*"); // 모든 HTTP 메서드 허용
        config.addAllowedHeader("*"); // 모든 헤더 허용
        config.setAllowCredentials(true); // 인증 정보 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }


}