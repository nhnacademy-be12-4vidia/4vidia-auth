package com.nhnacademy._vidiaauth.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nhnacademy._vidiaauth.dto.CustomUserDetails;
import com.nhnacademy._vidiaauth.dto.LoginRequest;
import com.nhnacademy._vidiaauth.dto.AuthUserDto;
import com.nhnacademy._vidiaauth.repository.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.*;

class LoginFilterTest {

    private LoginFilter loginFilter;
    private AuthenticationManager authenticationManager;
    private JwtUtil jwtUtil;
    private JweUtil jweUtil;
    private TokenService tokenService;
    private ObjectMapper objectMapper;


    @BeforeEach
    void setUp() {
        authenticationManager = mock(AuthenticationManager.class);
        jwtUtil = mock(JwtUtil.class);
        jweUtil = mock(JweUtil.class);
        tokenService = mock(TokenService.class);

        objectMapper = new ObjectMapper();
        // Java 8 LocalDateTime 지원
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        loginFilter = new LoginFilter(
                authenticationManager,
                jwtUtil,
                jweUtil,
                tokenService,
                objectMapper
        );
    }


    @Test
    void successfulAuthenticationShouldReturnAccessAndRefreshToken() throws Exception {
        // given
        LoginRequest loginRequest = new LoginRequest("test@test.com", "password");
        String json = objectMapper.writeValueAsString(loginRequest);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContent(json.getBytes(StandardCharsets.UTF_8));
        request.setContentType("application/json");

        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthUserDto userInfo = new AuthUserDto(
                1L,
                "test@test.com",
                "",
                "ROLE_USER",
                "ACTIVE"
        );

        CustomUserDetails userDetails = new CustomUserDetails(userInfo);

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
                );

        given(authenticationManager.authenticate(any()))
                .willReturn(authentication);

        given(jwtUtil.createToken(any(), any(), anyLong(), eq("access"), any()))
                .willReturn("access.jwt.token");

        given(jwtUtil.createToken(any(), any(), anyLong(), eq("refresh"), any()))
                .willReturn("refresh.jwt.token");

        given(jweUtil.encrypt("access.jwt.token"))
                .willReturn("encrypted.access.token");

        // when
        Authentication authResult = loginFilter.attemptAuthentication(request, response);
        loginFilter.successfulAuthentication(request, response, null, authResult);

        // then
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsString()).contains("encrypted.access.token");

        verify(tokenService, times(1))
                .saveToken(anyString(), eq("refresh.jwt.token"), anyLong());
    }

    @Test
    void unsuccessfulAuthenticationShouldReturnUnauthorized() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        loginFilter.unsuccessfulAuthentication(request, response, null);

        assertThat(response.getStatus()).isEqualTo(401);
    }
}
