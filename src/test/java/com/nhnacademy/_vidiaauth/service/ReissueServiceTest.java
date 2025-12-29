package com.nhnacademy._vidiaauth.service;

import com.nhnacademy._vidiaauth.dto.TokenResponse;
import com.nhnacademy._vidiaauth.jwt.JweUtil;
import com.nhnacademy._vidiaauth.jwt.JwtUtil;
import com.nhnacademy._vidiaauth.repository.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ReissueServiceTest {

    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private TokenService tokenService;
    @Mock
    private JweUtil jweUtil;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private ReissueService reissueService;

    @Test
    void reissueTokens_success() throws Exception {
        // given
        String refreshUuid = "uuid";
        String refreshToken = "refresh-token";

        when(tokenService.getToken(refreshUuid)).thenReturn(refreshToken);
        when(jwtUtil.isTokenValid(refreshToken)).thenReturn(true);
        when(jwtUtil.getType(refreshToken)).thenReturn("refresh");
        when(jwtUtil.getUserId(refreshToken)).thenReturn(1L);
        when(jwtUtil.getRoles(refreshToken)).thenReturn("ROLE_USER");
        when(jwtUtil.getStatus(refreshToken)).thenReturn("ACTIVE");
        when(jwtUtil.createToken(any(), any(), anyLong(), any(), any()))
                .thenReturn("jwt-token");
        when(jweUtil.encrypt(any())).thenReturn("jwe-token");

        // when
        TokenResponse result =
                reissueService.reissueTokens(request, response, refreshUuid);

        // then
        assertThat(result).isNotNull();
        assertThat(result.accessToken()).isEqualTo("jwe-token");

        verify(tokenService).deleteToken(refreshUuid);
        verify(tokenService).saveToken(any(), any(), anyLong());
    }
    @Test
    void reissueTokens_fail_whenTokenNotFound() throws Exception {
        when(tokenService.getToken("uuid")).thenReturn(null);

        TokenResponse result =
                reissueService.reissueTokens(request, response, "uuid");

        assertThat(result).isNull();
    }
}
