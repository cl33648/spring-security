package com.example.security.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {

    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public JwtTokenVerifier(SecretKey secretKey, JwtConfig jwtConfig) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    //invoke the filter once per every single request
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        //String authorizationHeader = request.getHeader("Authorization");
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

        //the request will be rejected if the authorizationHeader(token) is invalid: null or doesn't start with "Bearer "
        //if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")){
        if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())){
            filterChain.doFilter(request,response);
            return;
        }

        //replace authorizationHeader(token) with token value but Bearer part removed
        //String token = authorizationHeader.replace("Bearer ", "");
        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

        try{
            //String secretKey = "securesecuresecuresecuresecuresecuresecuresecuresecure";

            //parse(break up each part of) actual token
            Jws<Claims> claimsJws = Jwts.parser()
                    //.setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))    //key from JwtUsernameAndPasswordAuthenticationFilter
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);

            Claims body = claimsJws.getBody();
            String username = body.getSubject();
            var authorities = (List<Map<String,String>>) body.get("authorities");

            //JWT token body claims "authorities" - student:write, student:read, course:read, course:write, ROLE_ADMIN etc.
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities
            );

            //client that sends the token is now authenticated
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch(JwtException e){
            //invalid token or expired token
            throw new IllegalStateException(String.format("Token %s cannot be trusted.", token));
        }

        filterChain.doFilter(request,response);

    }
}
