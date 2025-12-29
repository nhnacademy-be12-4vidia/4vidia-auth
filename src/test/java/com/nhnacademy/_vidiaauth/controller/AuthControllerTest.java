package com.nhnacademy._vidiaauth.jwt;

import com.nhnacademy._vidiaauth.controller.AuthController;
import com.nhnacademy._vidiaauth.dto.ApiResponse;
import com.nhnacademy._vidiaauth.dto.TokenResponse;
import com.nhnacademy._vidiaauth.dto.UserGatewayResponse;
import com.nhnacademy._vidiaauth.repository.TokenService;
import com.nhnacademy._vidiaauth.service.ReissueService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerTest {

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    JwtUtil jwtUtil;

    @MockitoBean
    JweUtil jweUtil;

    @MockitoBean
    TokenService tokenService;

    @MockitoBean
    ReissueService reissueService;

    @Test
    void requestWithoutCookiesShouldReturnUnauthorizedForValidate() throws Exception {
        mockMvc.perform(post("/internal/validate"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validateWithValidSesCookieShouldReturnUserGatewayResponse() throws Exception {
        String sesToken = "validSesToken";
        String decryptedSes = "decryptedSesToken";

        Cookie sesCookie = new Cookie("SES", sesToken);

        given(jweUtil.decrypt(sesToken)).willReturn(decryptedSes);
        given(jwtUtil.isTokenValid(decryptedSes)).willReturn(true);
        given(jwtUtil.getUserId(decryptedSes)).willReturn(1L);
        given(jwtUtil.getRoles(decryptedSes)).willReturn("ROLE_USER");
        given(jwtUtil.getStatus(decryptedSes)).willReturn("ACTIVE");

        mockMvc.perform(post("/internal/validate").cookie(sesCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1L))
                .andExpect(jsonPath("$.roles").value("ROLE_USER"))
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    void logoutShouldCallDeleteToken() throws Exception {
        Long userId = 1L;
        Cookie autCookie = new Cookie("AUT", "refreshToken");

        mockMvc.perform(post("/auth/logout")
                        .cookie(autCookie)
                        .header("X-User-Id", userId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.header.isSuccessful").value(true));

        Mockito.verify(tokenService).deleteToken("refreshToken");
    }

    @Test
    void reissueTokensShouldReturnSuccess() throws Exception {
        String refreshUuid = "refresh123";
        TokenResponse tokenResponse = new TokenResponse("accessToken", "refreshUuid");

        given(reissueService.reissueTokens(Mockito.any(), Mockito.any(), Mockito.anyString()))
                .willReturn(new TokenResponse("accessToken", "refreshUuid"));

        mockMvc.perform(post("/auth/reissue")
                        .contentType("application/json")
                        .content("\"" + refreshUuid + "\""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.header.isSuccessful").value(true))
                .andExpect(jsonPath("$.data.accessToken").value("accessToken"))
                .andExpect(jsonPath("$.data.refreshUuid").value("refreshUuid"));
    }
    @Test
    void validateWithoutAnyCookiesShouldReturnUnauthorized() throws Exception {
        mockMvc.perform(post("/internal/validate"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validateWithValidAutOnlyShouldReturnNewSes() throws Exception {
        String autToken = "validAutToken";
        String decryptedAut = "decryptedAut";

        Cookie autCookie = new Cookie("AUT", autToken);

        given(jweUtil.decrypt(autToken)).willReturn(decryptedAut);
        given(jwtUtil.isTokenValid(decryptedAut)).willReturn(true);
        given(jwtUtil.getUserId(decryptedAut)).willReturn(2L);
        given(jwtUtil.getRoles(decryptedAut)).willReturn("ROLE_ADMIN");
        given(jwtUtil.getStatus(decryptedAut)).willReturn("ACTIVE");
        given(jwtUtil.createToken(2L, "ROLE_ADMIN", 1000L*60*30, "access", "ACTIVE"))
                .willReturn("newSesToken");
        given(jweUtil.encrypt("newSesToken")).willReturn("encryptedSesToken");

        mockMvc.perform(post("/internal/validate").cookie(autCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(2L))
                .andExpect(jsonPath("$.roles").value("ROLE_ADMIN"))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, org.hamcrest.Matchers.containsString("SES=encryptedSesToken")));
    }

    @Test
    void validateWithExpiredSesAndInvalidAutShouldReturnUnauthorized() throws Exception {
        String sesToken = "expiredSesToken";
        Cookie sesCookie = new Cookie("SES", sesToken);

        given(jweUtil.decrypt(sesToken)).willReturn("decryptedSesExpired");
        given(jwtUtil.isTokenValid("decryptedSesExpired")).willReturn(false);

        mockMvc.perform(post("/internal/validate").cookie(sesCookie))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void reissueTokensWithInvalidRefreshUuidShouldReturnUnauthorized() throws Exception {
        String refreshUuid = "invalidUuid";

        given(reissueService.reissueTokens(Mockito.any(), Mockito.any(), Mockito.eq(refreshUuid)))
                .willReturn(null);

        mockMvc.perform(post("/auth/reissue")
                        .contentType("application/json")
                        .content("\"" + refreshUuid + "\""))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.header.isSuccessful").value(false))
                .andExpect(jsonPath("$.header.resultCode").value(401))
                .andExpect(jsonPath("$.header.resultMessage").value("Token reissue failed"));
    }

    @Test
    void logoutWithoutCookieShouldSucceed() throws Exception {
        Long userId = 1L;

        mockMvc.perform(post("/auth/logout")
                        .header("X-User-Id", userId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.header.isSuccessful").value(true));

        Mockito.verify(tokenService, Mockito.never()).deleteToken(Mockito.anyString());
    }

    @Test
    void logoutWithNonAutCookieShouldSucceed() throws Exception {
        Long userId = 1L;
        Cookie someCookie = new Cookie("OTHER", "value");

        mockMvc.perform(post("/auth/logout")
                        .cookie(someCookie)
                        .header("X-User-Id", userId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.header.isSuccessful").value(true));

        Mockito.verify(tokenService, Mockito.never()).deleteToken(Mockito.anyString());
    }



}
