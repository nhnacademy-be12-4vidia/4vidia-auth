package com.nhnacademy._vidiaauth.dto;

// 프론트 -> auth
public record LoginRequest(
        String email,
        String password
) {}