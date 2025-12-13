package com.nhnacademy._vidiaauth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy._vidiaauth.jwt.JwtFilter;
import com.nhnacademy._vidiaauth.jwt.JwtUtil;
import com.nhnacademy._vidiaauth.jwt.LoginFilter;
import com.nhnacademy._vidiaauth.repository.RefreshTokenService;
import com.nhnacademy._vidiaauth.service.CustomUserDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;
    private final ObjectMapper objectMapper;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    // repository 추가
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // JWT방식에서는 세션을 stateless로 관리하기때문에 csrf에 대한 공격을 방어하지 않아도 된다.
        // 그리고 refresh토큰을 HttpOnly쿠키에 담을건데 csrf공격은 쿠키 자동 전송 + 쿠키로 인증을
        // 이용하는 것인데 refresh토큰은 인증이 아닌 access토큰 발급용으로 공격을 방어하지 않아도됀다.
        http
                .csrf((auth) -> auth.disable());
        // 세션을 stateless로 설정(JWT 방식이니) 즉 jwt를 세션에 저장하지 않을거야.
        http
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // JWT방식으로 로그인 할거기 때문에 둘다 disable한다.
        // 기본 로그인 페이지 비활성화 (JSON 방식으로 인증할거라)
        http
                .formLogin((auth) -> auth.disable());
        // 헤더에 아이디/비밀번호를 Base64로 담아 인증하는 방식(Basic Auth)을 끈다.
        http
                .httpBasic((auth) -> auth.disable());

        // 인가
        http
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("/auth/**", "/login/**","/login/oauth2/**","/login/oauth2/code/payco").permitAll());
        http
                .addFilterBefore(new JwtFilter(jwtUtil,refreshTokenService ), LoginFilter.class);

        LoginFilter loginFilter = new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshTokenService, objectMapper);
        loginFilter.setFilterProcessesUrl("/auth/login"); // 이걸 지정해야 /auth/login 요청을 잡습니다.

        http
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

}
