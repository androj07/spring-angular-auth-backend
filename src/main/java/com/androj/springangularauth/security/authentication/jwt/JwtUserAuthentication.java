package com.androj.springangularauth.security.authentication.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Base64;
import java.util.Date;

public class JwtUserAuthentication {

    private final UserDetailsService userDetailsService;
    private final JwtTokenProvider jwtTokenProvider;
    private final String secret;

    public JwtUserAuthentication(UserDetailsService userDetailsService, JwtTokenProvider jwtTokenProvider, String secret) {
        this.userDetailsService = userDetailsService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.secret = Base64.getEncoder().encodeToString(secret.getBytes());
    }

    public Authentication getAuthentication(String jwtToken) {
        String user = this.extractUserNameFromToken(jwtToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(user);
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String generateToken(String userName){
        UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
        return jwtTokenProvider.createToken(userDetails,secret);
    }



    private String extractUserNameFromToken(String jwtToken) {
        return Jwts.parser().setSigningKey(this.secret).parseClaimsJws(jwtToken).getBody().getSubject();
    }

    public boolean isValidToken(String jwtToken) {
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(secret).parseClaimsJws(jwtToken);
        Date expiration = claimsJws.getBody().getExpiration();
        return expiration.after(new Date());
    }
}
