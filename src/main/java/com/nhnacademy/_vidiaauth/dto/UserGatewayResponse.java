package com.nhnacademy._vidiaauth.dto;

import lombok.Getter;

public record UserGatewayResponse(
        Long id,
        @Getter
        String roles,
        @Getter
        String status
) {}