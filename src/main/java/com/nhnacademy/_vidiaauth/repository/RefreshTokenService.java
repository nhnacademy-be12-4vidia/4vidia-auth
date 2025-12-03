package com.nhnacademy._vidiaauth.repository;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RefreshTokenService {

    private final RedisTemplate<String, String> redisTemplate;

    public RefreshTokenService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void saveRefreshToken(String email, String refreshToken, long expireMs) {
        redisTemplate.opsForValue().set(email, refreshToken, expireMs, TimeUnit.MILLISECONDS);
    }


    public String getRefreshToken(String email) {
        return redisTemplate.opsForValue().get(email);
    }


    public void deleteRefreshToken(String email) {
        redisTemplate.delete(email);
    }


    public boolean validateRefreshToken(String email, String token) {
        String storedToken = getRefreshToken(email);
        return storedToken != null && storedToken.equals(token);
    }
}
