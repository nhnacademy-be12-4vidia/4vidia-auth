package com.nhnacademy._vidiaauth.controller;

import com.nhnacademy._vidiaauth.client.UserClient;
import com.nhnacademy._vidiaauth.dto.*;
import com.nhnacademy._vidiaauth.jwt.JweUtil;
import com.nhnacademy._vidiaauth.jwt.JwtUtil;
import com.nhnacademy._vidiaauth.repository.TokenService;
import com.nhnacademy._vidiaauth.service.PaycoAuthService;
import com.nimbusds.jose.JOSEException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.UUID;

@Controller
@RequiredArgsConstructor
public class PaycoController {
    private final JwtUtil jwtUtil;
    private final PaycoAuthService paycoAuthService;
    private final UserClient userClient;
    private final TokenService tokenService;
    private final JweUtil jweUtil;
    @Value("${app.cookie.secure}")
    private boolean cookieSecure;
    @Value("${app.cookie.domain}")
    private String cookieDomain;

    @GetMapping("/login/payco")
    public void getPaycoUser(HttpServletResponse response) throws IOException {
        String redirectUrl = paycoAuthService.redirectToPayco();
        response.sendRedirect(redirectUrl);
    }

    @ResponseBody
    @PostMapping("/login/oauth2/code/payco")
    public ResponseEntity<TokenResponse> payCallback(@RequestBody PaycoCodeRequest paycoCodeRequest, HttpServletResponse response) throws IOException {
        // 토큰 요청, 회원 정보 조회, jwt 발급
//        /login/payco → Payco redirect
//        /login/oauth2/code/payco → code 받아 token 요청
//        /access-token 요청
//        /payco-member 조회
//        /내DB 조회 or 회원가입
//        /JWT 발급 → 프론트 반환
        PaycoTokenResponse token = paycoAuthService.getAccessToken(paycoCodeRequest.code());
        PaycoMemberResponse member = paycoAuthService.getMemberInfo(token.getAccessToken());
        String paycoId = member.getData().getMember().getIdNo();
        PaycoUserRequest paycoUserRequest = new PaycoUserRequest(paycoId);
        OAuth2UserDto paycoUserDto = userClient.findOrCreateByPaycoId(paycoUserRequest);
        String accessToken = jwtUtil.createToken(paycoUserDto.getUserId(), paycoUserDto.getRole(), 1000L * 60 * 30, "access", paycoUserDto.getStatus());
        String refreshToken = jwtUtil.createToken(paycoUserDto.getUserId(), paycoUserDto.getRole(), 1000L * 60 * 30, "refresh", paycoUserDto.getStatus());

        String refreshUuid = UUID.randomUUID().toString();
        String accessJweToken = null;
        try {
            accessJweToken = jweUtil.encrypt(accessToken);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        tokenService.saveToken(refreshUuid, refreshToken, 1000L * 60 * 60 * 24 * 7);

        TokenResponse tokenResponse = new TokenResponse(accessJweToken, refreshUuid);
        // 6. 프론트로 이동
        return ResponseEntity.ok().body(tokenResponse);
    }



}

