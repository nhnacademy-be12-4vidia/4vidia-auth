package com.nhnacademy._vidiaauth.service;
import com.nhnacademy._vidiaauth.client.UserClient;
import com.nhnacademy._vidiaauth.dto.CustomUserDetails;
import com.nhnacademy._vidiaauth.dto.UserInfoResponse;
import com.nhnacademy._vidiaauth.repository.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final TokenService tokenService;
    private final UserClient userClient;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserInfoResponse userInfo = userClient.getUserByEmail(email);

        // CustomUserDetails로 감싸서 반환
        return new CustomUserDetails(userInfo);
    }
}
