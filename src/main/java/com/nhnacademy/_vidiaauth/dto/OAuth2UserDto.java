package com.nhnacademy._vidiaauth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuth2UserDto {
    private Long userId;
    private String email;
    private String role;
    private String status;
}