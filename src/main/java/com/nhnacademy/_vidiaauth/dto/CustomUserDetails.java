package com.nhnacademy._vidiaauth.dto;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {
    private final AuthUserDto authUserDto;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return authUserDto.getRoles();
            }
        });
        return collection;
    }

    @Override
    public String getPassword() {
        return authUserDto.getPassword();
    }

    @Override
    public String getUsername() {
        return authUserDto.getEmail();
    }

    public Long getId() {
        return authUserDto.id();
    }

    public String getStatus() {
        return authUserDto.getStatus();
    }
}
