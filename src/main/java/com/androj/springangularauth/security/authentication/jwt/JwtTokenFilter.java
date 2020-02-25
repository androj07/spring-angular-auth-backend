package com.androj.springangularauth.security.authentication.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Optional;

public class JwtTokenFilter extends GenericFilterBean {

    private final JwtUserAuthentication jwtUserAuthentication;

    public JwtTokenFilter(JwtUserAuthentication jwtUserAuthentication) {
        this.jwtUserAuthentication = jwtUserAuthentication;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        Optional<String> eventualToken = this.resolveToken((HttpServletRequest) request);
        eventualToken.ifPresent((token) -> {
            if (jwtUserAuthentication.isValidToken(token)) {
                Authentication authentication = jwtUserAuthentication.getAuthentication(token);
                if (authentication != null) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        });
        chain.doFilter(request, response);

    }

    private Optional<String> resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return Optional.of(bearerToken.substring(7));
        }
        return Optional.empty();
    }
}
