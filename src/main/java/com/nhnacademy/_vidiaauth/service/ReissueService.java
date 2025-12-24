package com.nhnacademy._vidiaauth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy._vidiaauth.dto.TokenResponse;
import com.nhnacademy._vidiaauth.jwt.JweUtil;
import com.nhnacademy._vidiaauth.jwt.JwtUtil;
import com.nhnacademy._vidiaauth.repository.TokenService;
import com.nimbusds.jose.JOSEException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReissueService {
    private final JwtUtil jwtUtil;
    private final TokenService tokenService;
    private final JweUtil jweUtil;

    public TokenResponse reissueTokens(HttpServletRequest request, HttpServletResponse response, String refreshUuid) throws IOException {
        String refreshToken = tokenService.getToken(refreshUuid);
        tokenService.deleteToken(refreshUuid);

        if (refreshToken == null || refreshToken.isBlank()) {
            return null;
        }

        // 유효성 확인
        if (!jwtUtil.isTokenValid(refreshToken)
                || !"refresh".equals(jwtUtil.getType(refreshToken))) {
            return null;
        }

        // 새로운 Access Token 생성
        String newAccessToken = jwtUtil.createToken(
                jwtUtil.getUserId(refreshToken),
                jwtUtil.getEmail(refreshToken),
                jwtUtil.getRoles(refreshToken),
                1000L * 60 * 30, // 30분
                "access",
                jwtUtil.getStatus(refreshToken)
        );

        // 새 Refresh Token 생성
        String newRefreshToken = jwtUtil.createToken(
                jwtUtil.getUserId(refreshToken),
                jwtUtil.getEmail(refreshToken),
                jwtUtil.getRoles(refreshToken),
                1000L * 60 * 60 * 24 * 7, // 7일
                "refresh",
                jwtUtil.getStatus(refreshToken)
        );



        String accessJweToken = null;
        try {
            accessJweToken = jweUtil.encrypt(newAccessToken);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        // DB 저장
        String newRefreshUuid = UUID.randomUUID().toString();


        tokenService.saveToken(newRefreshUuid, newRefreshToken, 1000L * 60 * 60 * 24 * 7);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        TokenResponse tokenResponse = new TokenResponse(accessJweToken, newRefreshUuid);

        return tokenResponse;
    }
}
