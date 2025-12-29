package com.nhnacademy._vidiaauth.controller;

import com.nhnacademy._vidiaauth.client.UserClient;
import com.nhnacademy._vidiaauth.dto.*;
import com.nhnacademy._vidiaauth.jwt.JweUtil;
import com.nhnacademy._vidiaauth.jwt.JwtUtil;
import com.nhnacademy._vidiaauth.repository.TokenService;
import com.nhnacademy._vidiaauth.service.PaycoAuthService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PaycoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtUtil jwtUtil;

    @MockitoBean
    private JweUtil jweUtil;

    @MockitoBean
    private PaycoAuthService paycoAuthService;

    @MockitoBean
    private UserClient userClient;

    @MockitoBean
    private TokenService tokenService;

    @Test
    void getPaycoUserShouldRedirect() throws Exception {
        String redirectUrl = "https://payco.example.com/oauth";
        given(paycoAuthService.redirectToPayco()).willReturn(redirectUrl);

        mockMvc.perform(get("/login/payco"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(redirectUrl));
    }

    @Test
    void payCallbackShouldReturnTokenResponse() throws Exception {
        String code = "paycoCode123";

        PaycoTokenResponse paycoToken = new PaycoTokenResponse(
                "accessToken123",
                "accessSecret",
                "refreshToken123",
                "bearer",
                "3600"
        );

        OAuth2UserDto userDto = new OAuth2UserDto(1L, "test@test.com", "ROLE_USER", "ACTIVE");

        String accessToken = "jwtAccessToken";
        String refreshToken = "jwtRefreshToken";
        String accessJweToken = "jweAccessToken";
        String refreshUuid = UUID.randomUUID().toString();

        PaycoMemberResponse.PaycoMember member = new PaycoMemberResponse.PaycoMember("paycoId123");
        PaycoMemberResponse.PaycoData data = new PaycoMemberResponse.PaycoData(member);
        PaycoMemberResponse memberResponse = new PaycoMemberResponse(data);

        // Mock 외부 서비스
        given(paycoAuthService.getAccessToken(anyString())).willReturn(paycoToken);
        given(paycoAuthService.getMemberInfo(paycoToken.getAccessToken())).willReturn(memberResponse);
        given(userClient.findOrCreateByPaycoId(any(PaycoUserRequest.class))).willReturn(userDto);
        given(jwtUtil.createToken(userDto.getUserId(), userDto.getRole(), 1000L * 60 * 30, "access", userDto.getStatus()))
                .willReturn(accessToken);
        given(jwtUtil.createToken(userDto.getUserId(), userDto.getRole(), 1000L * 60 * 30, "refresh", userDto.getStatus()))
                .willReturn(refreshToken);
        given(jweUtil.encrypt(accessToken)).willReturn(accessJweToken);
        Mockito.doNothing().when(tokenService).saveToken(anyString(), anyString(), any(Long.class));

        mockMvc.perform(post("/login/oauth2/code/payco")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"" + code + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value(accessJweToken))
                .andExpect(jsonPath("$.data.refreshUuid").exists());
    }
}
