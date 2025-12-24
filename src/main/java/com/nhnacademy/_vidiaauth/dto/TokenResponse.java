package com.nhnacademy._vidiaauth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record TokenResponse(
        String accessToken,
        String refreshUuid
) {}