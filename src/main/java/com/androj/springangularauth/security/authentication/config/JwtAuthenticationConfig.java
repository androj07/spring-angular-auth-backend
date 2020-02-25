package com.androj.springangularauth.security.authentication.config;

import com.androj.springangularauth.security.authentication.jwt.JwtUserAuthentication;
import com.androj.springangularauth.security.authentication.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
public class JwtAuthenticationConfig {
    @Value("${security.jwt.token.secret-key:secret}")
    private String jwtSecret;

    @Value("${security.jwt.token.expire-length:3600000}")
    private long validityInMilliseconds;


    @Bean
    JwtTokenProvider jwtTokenProvider() {
        return new JwtTokenProvider(validityInMilliseconds);
    }

    @Bean
    JwtUserAuthentication userAuthentication(UserDetailsService userDetailsService, JwtTokenProvider jwtTokenProvider) {
        return new JwtUserAuthentication(userDetailsService, jwtTokenProvider, jwtSecret);
    }
}
