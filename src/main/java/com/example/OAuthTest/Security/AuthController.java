package com.example.OAuthTest.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Query;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;



    @PostMapping
    public String login(@RequestParam String username){

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username,"123"));
        String token= jwtUtils.generateToken(username);


        return token;
    }
}
