package com.nhnacademy._vidiaauth.dto;

import lombok.Getter;

// 프론트 -> auth
public record LoginRequest(
        @Getter
        String email,
        @Getter
        String password
) {}