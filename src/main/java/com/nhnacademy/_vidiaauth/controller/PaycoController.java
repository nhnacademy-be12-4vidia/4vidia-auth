package com.nhnacademy._vidiaauth.controller;

import com.nhnacademy._vidiaauth.dto.PaycoMemberResponse;
import com.nhnacademy._vidiaauth.dto.PaycoTokenResponse;
import com.nhnacademy._vidiaauth.jwt.JwtUtil;
import com.nhnacademy._vidiaauth.service.PaycoAuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@Controller
@RequiredArgsConstructor
public class PaycoController {
    private final JwtUtil jwtUtil;
    private final PaycoAuthService paycoAuthService;
    @Value("${app.cookie.secure}")
    private boolean cookieSecure;
    @Value("${app.cookie.domain}")
    private String cookieDomain;

    @GetMapping("/login/payco")
    public void getPaycoUser(HttpServletResponse response) throws IOException {
        String redirectUrl = paycoAuthService.redirectToPayco();
        response.sendRedirect(redirectUrl);
    }

    @GetMapping("/login/oauth2/code/payco")
    public void payCallback(@RequestParam String code, @RequestParam(required = false) String state, HttpServletResponse response) throws IOException {
        // 토큰 요청, 회원 정보 조회, jwt 발급
//        /login/payco → Payco redirect
//        /login/oauth2/code/payco → code 받아 token 요청
//        /access-token 요청
//        /payco-member 조회
//        /내DB 조회 or 회원가입
//        /JWT 발급 → 프론트 반환
        PaycoTokenResponse token = paycoAuthService.getAccessToken(code);
        PaycoMemberResponse member = paycoAuthService.getMemberInfo(token.getAccessToken());
        String id = member.getData().getMember().getIdNo();
        String email = member.getData().getMember().getEmail();
        String name = member.getData().getMember().getName();
        String mobile = member.getData().getMember().getMobile();
        String accessToken = jwtUtil.createToken(10L, email, "ROLE_USER", 1000L * 60 * 30, "access");
        addCookie(response, "ACCESS_TOKEN", accessToken, 1800);

        System.out.println(member);

        // 6. 프론트로 이동
        response.sendRedirect("https://4vidia.shop");
    }

//    private void addCookie(HttpServletResponse response,
//                           String name,
//                           String value,
//                           int maxAge) {
//
//        Cookie cookie = new Cookie(name, value);
//        cookie.setHttpOnly(true);
//        cookie.setSecure(cookieSecure); // HTTPS
//        cookie.setPath("/");
//        cookie.setMaxAge(maxAge);
//        if (cookieDomain != null && !cookieDomain.isBlank()) {
//            cookie.setDomain(cookieDomain);
//        }
//
//        response.addCookie(cookie);
//    }
private void addCookie(HttpServletResponse response,
                       String name,
                       String value,
                       int maxAge) {

    StringBuilder cookieBuilder = new StringBuilder();
    cookieBuilder.append(name).append("=").append(value)
            .append("; Max-Age=").append(maxAge)
            .append("; Path=/")
            .append("; HttpOnly")
            .append("; Secure")
            .append("; SameSite=None"); // 중요

    if (cookieDomain != null && !cookieDomain.isBlank()) {
        cookieBuilder.append("; Domain=").append(cookieDomain);
    }

    response.addHeader("Set-Cookie", cookieBuilder.toString());
}
}

