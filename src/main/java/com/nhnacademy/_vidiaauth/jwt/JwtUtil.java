package com.nhnacademy._vidiaauth.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {
    private final SecretKey secretKey;

    public JwtUtil(@Value("${spring.jwt.secret}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String createToken(Long id, String email, String roles, long expirationMs, String type) {
        return Jwts.builder()
                .setSubject(email)
                .claim("id", id)
                .claim("roles", roles)
                .claim("type", type)  // access / refresh
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims parseClaims(String token) throws JwtException {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isTokenValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            parseClaims(token);
            return false;
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    public String getType(String token) {
        return parseClaims(token).get("type", String.class);
    }

    public Long getUserId(String token) {
        return parseClaims(token).get("id", Long.class);
    }

    public String getRoles(String token) {
        return parseClaims(token).get("roles", String.class);
    }

    public String getEmail(String token) {
        return parseClaims(token).getSubject();
    }
}
