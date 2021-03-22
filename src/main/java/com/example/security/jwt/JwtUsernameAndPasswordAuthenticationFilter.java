package com.example.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

//this class verifies the user credentials and sends JWT back to the client
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        try {
            //grab the username and password from UsernameAndPasswordAuthenticationRequest.java
            //ObjectMapper reads the value from input stream and puts the values into authenticationRequest
            UsernameAndPasswordAuthenticationRequest authenticationRequest =
                    new ObjectMapper().readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            //UsernamePasswordAuthenticationToken implements Authentication interface
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

            Authentication authenticate = authenticationManager.authenticate(authentication);
            return authenticate;

        }catch(IOException e){
            throw new RuntimeException(e);
        }

    }

    //invoked after the attemptAuthentication is successful
    //creates and send the token to the client
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        String key = "securesecuresecuresecuresecuresecuresecuresecuresecure";      //make sure the key is long enough, so nobody can guess it

        String token = Jwts.builder()
                .setSubject(authResult.getName())                                   //linda, tom, annasmith etc
                .claim("authorities", authResult.getAuthorities())               //body
                .setIssuedAt(new Date())
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2))) //token expires after 2 weeks
                .signWith(Keys.hmacShaKeyFor(key.getBytes()))
                .compact();

        //add the token to the response so that client can retrieve it for subsequent requests
        //send the token back to the client
        response.addHeader("Authorization", "Bearer "+token);

    }
}
