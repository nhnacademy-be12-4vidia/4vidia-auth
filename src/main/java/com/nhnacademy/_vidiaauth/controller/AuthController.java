package com.nhnacademy._vidiaauth.controller;

import com.nhnacademy._vidiaauth.dto.TokenResponse;
import com.nhnacademy._vidiaauth.repository.RefreshTokenService;
import com.nhnacademy._vidiaauth.service.ReissueService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final ReissueService reissueService;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/auth/login")
    public ResponseEntity<TokenResponse> getUser(){
        //UserResponse <-- 각 팀별로 설계한 회원 스키마를 고려하여 수정합니다.
        //X-USER-ID는 Gateway에서 access-token을 검증 후 valid한 token이면 jwt의 payload의 userId를 Header에  X-USER-ID로 추가 합니다.
        //회원은 shoppingmall-api 서버에 회원을 조회할 수 있는 api를 개발<-- 해당 API를 호출 합니다.
        return ResponseEntity.ok(new TokenResponse("",""));
    }

    @PostMapping("/auth/reissue")
    public ResponseEntity<TokenResponse> reissueTokens(HttpServletRequest request, HttpServletResponse response) throws IOException {
        TokenResponse tokenResponse = reissueService.reissueTokens(request, response);

        if (tokenResponse == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        return ResponseEntity.ok(tokenResponse);
    }
    @PostMapping("/auth/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        String refreshToken = getRefreshTokenFromCookie(request);
        if (refreshToken != null) {
            refreshTokenService.deleteRefreshToken(refreshToken);
        }
        return ResponseEntity.ok().build();
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
