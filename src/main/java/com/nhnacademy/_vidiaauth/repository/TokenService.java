package com.nhnacademy._vidiaauth.repository;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenService {

    private final RedisTemplate<String, String> redisTemplate;

    public TokenService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void saveToken(String sessionId, String refreshToken, long expireMs) {
        redisTemplate.opsForValue().set(sessionId, refreshToken, expireMs, TimeUnit.MILLISECONDS);
    }


    public String getToken(String sessionId) {
        return redisTemplate.opsForValue().get(sessionId);
    }


    public void deleteToken(String sessionId) {
        redisTemplate.delete(sessionId);
    }


    public boolean validateToken(String sessionId, String token) {
        String storedToken = getToken(sessionId);
        return storedToken != null && storedToken.equals(token);
    }
}
