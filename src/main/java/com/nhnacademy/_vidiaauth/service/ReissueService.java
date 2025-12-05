package com.nhnacademy._vidiaauth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy._vidiaauth.dto.TokenResponse;
import com.nhnacademy._vidiaauth.jwt.JwtUtil;
import com.nhnacademy._vidiaauth.repository.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class ReissueService {
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final ObjectMapper objectMapper;

    public TokenResponse reissueTokens(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String refreshToken = getRefreshTokenFromCookie(request);

        if (refreshToken == null || refreshToken.isBlank()) {
            return null;
        }

        // 유효성 확인
        if (!jwtUtil.isTokenValid(refreshToken)
                || !"refresh".equals(jwtUtil.getType(refreshToken))
                || !refreshTokenService.validateRefreshToken(jwtUtil.getEmail(refreshToken), refreshToken)) {
            return null;
        }

        // 새로운 Access Token 생성
        String newAccessToken = jwtUtil.createToken(
                jwtUtil.getUserId(refreshToken),
                jwtUtil.getEmail(refreshToken),
                jwtUtil.getRoles(refreshToken),
                1000L * 60 * 30, // 30분
                "access"
        );

        // 새 Refresh Token 생성 (선택 사항: 기존 Refresh Token 교체)
        String newRefreshToken = jwtUtil.createToken(
                jwtUtil.getUserId(refreshToken),
                jwtUtil.getEmail(refreshToken),
                jwtUtil.getRoles(refreshToken),
                1000L * 60 * 60 * 24 * 7, // 7일
                "refresh"
        );

        // Redis 또는 DB에 새 Refresh Token 저장
        refreshTokenService.saveRefreshToken(jwtUtil.getEmail(refreshToken), newRefreshToken, 1000L * 60 * 60 * 24 * 7);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        TokenResponse tokenResponse = new TokenResponse(newAccessToken, newRefreshToken);

        return tokenResponse;
    }

    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if ("refresh".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
