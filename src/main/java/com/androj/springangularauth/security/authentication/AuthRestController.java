package com.androj.springangularauth.security.authentication;

import com.androj.springangularauth.security.authentication.jwt.JwtUserAuthentication;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthRestController {

    private final AuthenticationManager authenticationManager;
    private final JwtUserAuthentication userAuthentication;

    public AuthRestController(AuthenticationManager authenticationManager, JwtUserAuthentication userAuthentication) {
        this.authenticationManager = authenticationManager;
        this.userAuthentication = userAuthentication;
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody AuthBody authBody) {
        String login = authBody.getLogin();
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(login, authBody.getPassword()));
        String generatedToken = userAuthentication.generateToken(login);
        Map<String, String> authPayload = new HashMap<>();
        authPayload.put("login", login);
        authPayload.put("token", generatedToken);
        return ResponseEntity.ok(authPayload);
    }


}

