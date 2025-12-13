package com.nhnacademy._vidiaauth.controller;

import com.nhnacademy._vidiaauth.dto.PaycoMemberResponse;
import com.nhnacademy._vidiaauth.dto.PaycoTokenResponse;
import com.nhnacademy._vidiaauth.service.PaycoAuthService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
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
    private final PaycoAuthService paycoAuthService;

    @PostMapping("/auth/login/payco")
    public void getPaycoUser(HttpServletResponse response) throws IOException {
        String redirectUrl = paycoAuthService.redirectToPayco();
        response.sendRedirect(redirectUrl);
    }

    @GetMapping("/login/oauth2/code/payco")
    public String payCallback(@RequestParam String code) {
        // 토큰 요청, 회원 정보 조회, jwt 발급
        PaycoTokenResponse token = paycoAuthService.getAccessToken(code);
        PaycoMemberResponse member = paycoAuthService.getMemberInfo(token.getAccessToken());

        return "";
    }

    @GetMapping("/auth/test")
    public void getPaycoUser2(HttpServletResponse response) throws IOException {
        String redirectUrl = paycoAuthService.redirectToPayco();
        response.sendRedirect(redirectUrl);
    }
}

