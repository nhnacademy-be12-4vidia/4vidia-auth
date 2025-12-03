package com.nhnacademy._vidiaauth.dto;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {
    private final UserInfoResponse userInfoResponse;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return userInfoResponse.getRoles();
            }
        });
        return collection;
    }

    @Override
    public String getPassword() {
        return userInfoResponse.getPassword();
    }

    @Override
    public String getUsername() {
        return userInfoResponse.getEmail();
    }

    public Long getId() {
        return userInfoResponse.id();
    }
}
