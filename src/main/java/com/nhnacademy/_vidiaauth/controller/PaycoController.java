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

    @GetMapping("/login/payco")
    public void getPaycoUser(HttpServletResponse response) throws IOException {
        String redirectUrl = paycoAuthService.redirectToPayco();
        response.sendRedirect(redirectUrl);
    }

    @GetMapping("/login/oauth2/code/payco")
    public String payCallback(@RequestParam String code, @RequestParam(required = false) String state) {
        // 토큰 요청, 회원 정보 조회, jwt 발급
//        /login/payco → Payco redirect
//        /login/oauth2/code/payco → code 받아 token 요청
//        /access-token 요청
//        /payco-member 조회
//        /내DB 조회 or 회원가입
//        /JWT 발급 → 프론트 반환
        PaycoTokenResponse token = paycoAuthService.getAccessToken(code, state);
        PaycoMemberResponse member = paycoAuthService.getMemberInfo(token.getAccessToken());
        System.out.println(member);

        return "";
    }


}

