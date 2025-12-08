package com.nhnacademy._vidiaauth.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy._vidiaauth.dto.CustomUserDetails;
import com.nhnacademy._vidiaauth.dto.LoginRequest;
import com.nhnacademy._vidiaauth.dto.TokenResponse;
import com.nhnacademy._vidiaauth.repository.RefreshTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final ObjectMapper objectMapper;


    public LoginFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil, RefreshTokenService refreshTokenService, ObjectMapper objectMapper) {
        super(authenticationManager);
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
        this.objectMapper = objectMapper;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        LoginRequest loginRequest;

        try {
            loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),   // username은 이메일
                        loginRequest.getPassword()
                );

        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        CustomUserDetails user = (CustomUserDetails) authentication.getPrincipal();

        Long userId = user.getId();
        String email = user.getUsername();
        String roles = user.getAuthorities().iterator().next().getAuthority();

        String accessToken = jwtUtil.createToken(userId, email, roles, 1000L * 20 * 30, "access");  // 30분
        String refreshToken = jwtUtil.createToken(userId, email, roles, 1000L * 60 * 60 * 24 * 7, "refresh"); // 7일

        // DB 저장
        saveRefreshToken(email, refreshToken, 1000L * 60 * 60 * 24 * 7);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        TokenResponse tokenResponse = new TokenResponse(accessToken, refreshToken);
        response.getWriter().write(objectMapper.writeValueAsString(tokenResponse));
        response.setStatus(HttpStatus.OK.value());
    }


    private void saveRefreshToken(String email, String refreshToken, long expiredMs) {
        refreshTokenService.saveRefreshToken(email, refreshToken,expiredMs);
    }

    @Override
    protected void unsuccessfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException failed
    ) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
