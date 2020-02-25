package com.androj.springangularauth.security.authentication.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Base64;
import java.util.Date;

public class JwtTokenProvider {

    private final long tokenValidityInMillis;

    public JwtTokenProvider(long tokenValidityInMillis) {
        this.tokenValidityInMillis = tokenValidityInMillis;
    }

    public String createToken(UserDetails userDetails, String secret) {
        Claims claims = Jwts.claims().setSubject(userDetails.getUsername());
        claims.put("roles", userDetails.getAuthorities());
        Date tokenCreationTime = new Date();
        Date tokenExpirationTime = new Date(tokenCreationTime.getTime() + this.tokenValidityInMillis);
        return Jwts.builder()//
                .setClaims(claims)//
                .setIssuedAt(tokenCreationTime)//
                .setExpiration(tokenExpirationTime)//
                .signWith(SignatureAlgorithm.HS256, secret)//
                .compact();
    }
}
