package com.nhnacademy._vidiaauth.jwt;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JwtUtilTest {

    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        String secret = "qwertyuiopasdfghjklzxcvbnmqwertyuiop";
        jwtUtil = new JwtUtil(secret);
    }

    @Test
    void createTokenShouldContainCorrectClaims() {
        String token = jwtUtil.createToken(
                1L,
                "ROLE_USER",
                1000L * 60,
                "access",
                "ACTIVE"
        );

        Claims claims = jwtUtil.parseClaims(token);

        assertThat(claims.get("id", Long.class)).isEqualTo(1L);
        assertThat(claims.get("roles", String.class)).isEqualTo("ROLE_USER");
        assertThat(claims.get("type", String.class)).isEqualTo("access");
        assertThat(claims.get("userStatus", String.class)).isEqualTo("ACTIVE");
    }

    @Test
    void tokenShouldBeValid() {
        String token = jwtUtil.createToken(
                1L,
                "ROLE_USER",
                1000L * 60,
                "access",
                "ACTIVE"
        );

        assertThat(jwtUtil.isTokenValid(token)).isTrue();
        assertThat(jwtUtil.isTokenExpired(token)).isFalse();
    }

    @Test
    void invalidTokenShouldBeInvalid() {
        String invalidToken = "invalid.jwt.token";

        assertThat(jwtUtil.isTokenValid(invalidToken)).isFalse();
    }
}
