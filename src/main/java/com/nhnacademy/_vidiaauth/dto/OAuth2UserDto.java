package com.nhnacademy._vidiaauth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class OAuth2UserDto {
    private Long userId;
    private String email;
    private String role;
    private String status;
}