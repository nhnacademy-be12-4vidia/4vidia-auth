package com.nhnacademy._vidiaauth.controller;

import com.nhnacademy._vidiaauth.dto.TokenResponse;
import com.nhnacademy._vidiaauth.dto.UserGatewayResponse;
import com.nhnacademy._vidiaauth.dto.UserInfoResponse;
import com.nhnacademy._vidiaauth.jwt.JweUtil;
import com.nhnacademy._vidiaauth.jwt.JwtUtil;
import com.nhnacademy._vidiaauth.repository.TokenService;
import com.nhnacademy._vidiaauth.service.ReissueService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {
    private final ReissueService reissueService;
    private final TokenService tokenService;
    private final JwtUtil jwtUtil;
    private final JweUtil jweUtil;


    @PostMapping("/auth/login")
    public ResponseEntity<TokenResponse> getUser(){
        //UserResponse <-- 각 팀별로 설계한 회원 스키마를 고려하여 수정합니다.
        //X-USER-ID는 Gateway에서 access-token을 검증 후 valid한 token이면 jwt의 payload의 userId를 Header에  X-USER-ID로 추가 합니다.
        //회원은 shoppingmall-api 서버에 회원을 조회할 수 있는 api를 개발<-- 해당 API를 호출 합니다.
        return ResponseEntity.ok(new TokenResponse("",""));
    }

    @PostMapping("/auth/reissue")
    public ResponseEntity<TokenResponse> reissueTokens(HttpServletRequest request, HttpServletResponse response, @RequestBody String refreshUuid) throws IOException {
        log.info("재발급");
        TokenResponse tokenResponse = reissueService.reissueTokens(request, response, refreshUuid);

        if (tokenResponse == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        return ResponseEntity.ok(tokenResponse);
    }
    @PostMapping("/auth/logout")
    public ResponseEntity<String> logout(@RequestHeader("X-User-Id") Long userId, HttpServletRequest request) {
        log.info("로그아웃");
        String refreshToken = getRefreshTokenFromCookie(request);
        if (refreshToken != null) {
            tokenService.deleteToken(refreshToken);
        }
        return ResponseEntity.ok().body(String.valueOf(userId));
    }

    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if ("AUT".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    @PostMapping("/validate")
    public ResponseEntity<UserGatewayResponse> validateToken(@CookieValue(value = "SES", required = false) String ses, @CookieValue(value = "AUT", required = false) String aut, HttpServletResponse response) {
        log.info("jwt 유효성 검사");
        try {
            if (ses != null && jwtUtil.isTokenValid(jweUtil.decrypt(ses))) {
                String decryptedSes = jweUtil.decrypt(ses);

                Long userId = jwtUtil.getUserId(decryptedSes);
                String role = jwtUtil.getRoles(decryptedSes);
                String status = jwtUtil.getStatus(decryptedSes);

                return ResponseEntity.ok(new UserGatewayResponse(userId, role, status));
            }

            if (aut != null && jwtUtil.isTokenValid(jweUtil.decrypt(aut))) {
                String decryptedAut = jweUtil.decrypt(aut);

                // 새로운 SES 생성 (예: 30분)
                String newSes = jwtUtil.createToken(
                        jwtUtil.getUserId(decryptedAut),
                        jwtUtil.getRoles(decryptedAut),
                        1000L * 60 * 30,  // 30분
                        "access",
                        "ACTIVE"
                );

                // SES 쿠키로 브라우저 전달
                ResponseCookie cookie = ResponseCookie.from("SES", jweUtil.encrypt(newSes))
                        .httpOnly(true)
                        .path("/")
                        .maxAge(60 * 60 * 24 * 7) //일주일
                        .build();
                response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

                Long userId = jwtUtil.getUserId(decryptedAut);
                String role = jwtUtil.getRoles(decryptedAut);
                String status = jwtUtil.getStatus(decryptedAut);

                return ResponseEntity.ok(new UserGatewayResponse(userId, role, status));
            }

            // SES, AUT 둘 다 없거나 유효하지 않음 → 로그인 필요
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

}
