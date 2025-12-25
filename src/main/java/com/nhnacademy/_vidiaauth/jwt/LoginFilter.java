package com.nhnacademy._vidiaauth.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy._vidiaauth.dto.CustomUserDetails;
import com.nhnacademy._vidiaauth.dto.LoginRequest;
import com.nhnacademy._vidiaauth.dto.TokenResponse;
import com.nhnacademy._vidiaauth.repository.TokenService;
import com.nimbusds.jose.JOSEException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.UUID;

@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final JweUtil jweUtil;
    private final TokenService tokenService;
    private final ObjectMapper objectMapper;

    public LoginFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil, JweUtil jweUtil, TokenService tokenService, ObjectMapper objectMapper) {
        super(authenticationManager);
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.jweUtil = jweUtil;
        this.tokenService = tokenService;
        this.objectMapper = objectMapper;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String traceId = request.getHeader("X-Trace-Id");
        if (traceId == null) {
            traceId = UUID.randomUUID().toString();
        }
        MDC.put("traceId", traceId);
        log.info("인증시도");

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
        try {
            CustomUserDetails user = (CustomUserDetails) authentication.getPrincipal();
            Long userId = user.getId();
            log.info("userId:{}-인증성공", userId);
            String roles = user.getAuthorities().iterator().next().getAuthority();

            String accessToken = jwtUtil.createToken(userId, roles, 1000L * 60 * 30, "access", "ACTIVE");  // 30분
            String refreshToken = jwtUtil.createToken(userId, roles, 1000L * 60 * 60 * 24 * 7, "refresh", "ACTIVE"); // 7일

            String refreshUuid = UUID.randomUUID().toString();
            String accessJweToken = null;
            try {
                accessJweToken = jweUtil.encrypt(accessToken);
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }

            // DB 저장
            tokenService.saveToken(refreshUuid, refreshToken, 1000L * 60 * 60 * 24 * 7);

            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            TokenResponse tokenResponse = new TokenResponse(accessJweToken, refreshUuid);
            response.getWriter().write(objectMapper.writeValueAsString(tokenResponse));
            response.setStatus(HttpStatus.OK.value());

        }finally {
            MDC.clear();
        }

    }

    @Override
    protected void unsuccessfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException failed
    ) {
        try {
            log.info("인증실패");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        } finally {
            MDC.clear();
        }
    }
}
