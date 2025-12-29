package com.nhnacademy._vidiaauth.repository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.*;

class TokenServiceTest {

    private TokenService tokenService;
    private RedisTemplate<String, String> redisTemplate;
    private ValueOperations<String, String> valueOperations;

    @BeforeEach
    void setUp() {
        redisTemplate = mock(RedisTemplate.class);
        valueOperations = mock(ValueOperations.class);

        given(redisTemplate.opsForValue()).willReturn(valueOperations);

        tokenService = new TokenService(redisTemplate);
    }

    @Test
    void saveTokenShouldStoreValueWithTTL() {
        tokenService.saveToken("session-id", "refresh-token", 1000L);

        verify(valueOperations, times(1))
                .set("session-id", "refresh-token", 1000L, TimeUnit.MILLISECONDS);
    }

    @Test
    void getTokenShouldReturnStoredValue() {
        given(valueOperations.get("session-id"))
                .willReturn("refresh-token");

        String token = tokenService.getToken("session-id");

        assertThat(token).isEqualTo("refresh-token");
    }

    @Test
    void deleteTokenShouldRemoveValue() {
        tokenService.deleteToken("session-id");

        verify(redisTemplate, times(1))
                .delete("session-id");
    }

    @Test
    void validateTokenShouldReturnTrueWhenTokenMatches() {
        given(valueOperations.get("session-id"))
                .willReturn("refresh-token");

        boolean result = tokenService.validateToken("session-id", "refresh-token");

        assertThat(result).isTrue();
    }

    @Test
    void validateTokenShouldReturnFalseWhenTokenDoesNotMatch() {
        given(valueOperations.get("session-id"))
                .willReturn("other-token");

        boolean result = tokenService.validateToken("session-id", "refresh-token");

        assertThat(result).isFalse();
    }
}
