package com.nhnacademy._vidiaauth.jwt;

import com.nhnacademy._vidiaauth.dto.CustomUserDetails;
import com.nhnacademy._vidiaauth.dto.UserInfoResponse;
import com.nhnacademy._vidiaauth.repository.RefreshTokenService;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String path = request.getServletPath();
        if ("/auth/**".equals(path)) {
            filterChain.doFilter(request, response);
            return;
        }
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = authorization.substring(7);

        if (!jwtUtil.isTokenExpired(accessToken) && "access".equals(jwtUtil.getType(accessToken))) {
            setAuthentication(accessToken);
        } else {
            // Access token expired → refresh token 확인
            String refreshToken = getRefreshTokenFromCookie(request);
            if (refreshToken != null && !refreshToken.isBlank()
                    && jwtUtil.isTokenValid(refreshToken)
                    && "refresh".equals(jwtUtil.getType(refreshToken))
                    && refreshTokenService.validateRefreshToken(jwtUtil.getEmail(refreshToken), refreshToken)) {

                // 새 Access Token 발급
                String newAccessToken = jwtUtil.createToken(
                        jwtUtil.getUserId(refreshToken),
                        jwtUtil.getEmail(refreshToken),
                        jwtUtil.getRoles(refreshToken),
                        1000L * 60 * 30, // 30분
                        "access",
                        jwtUtil.getStatus(refreshToken)
                );

                response.setHeader("Authorization", "Bearer " + newAccessToken);

                // 새 Access Token으로 SecurityContext 설정
                setAuthentication(newAccessToken);

            } else {
                sendError(response, "Access token expired or refresh token invalid");
                return;
            }
        }


        filterChain.doFilter(request, response);
    }

    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if ("refresh".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private void sendError(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        PrintWriter writer = response.getWriter();
        writer.write(message);
        writer.flush();
    }

    private void setAuthentication(String token) {
        Long userId = jwtUtil.getUserId(token);
        String email = jwtUtil.getEmail(token);
        String roles = jwtUtil.getRoles(token);

        UserInfoResponse userInfoResponse = new UserInfoResponse(userId, email, "", roles);
        CustomUserDetails userDetails = new CustomUserDetails(userInfoResponse);

        Authentication authToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}
