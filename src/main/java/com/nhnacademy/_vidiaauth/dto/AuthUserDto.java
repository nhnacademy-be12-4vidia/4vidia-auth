package com.nhnacademy._vidiaauth.dto;

import lombok.Getter;

// user-service -> auth
public record AuthUserDto(
        @Getter
        Long id,
        @Getter
        String email,
        @Getter
        String password,
        @Getter
        String roles,
        @Getter// "ROLE_USER", "ROLE_ADMIN"
        String status
) {}