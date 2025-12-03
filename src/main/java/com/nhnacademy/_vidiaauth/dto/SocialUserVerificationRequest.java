package com.nhnacademy._vidiaauth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

// auth -> user-service
public record SocialUserVerificationRequest(
        String provider,
        @JsonProperty("provider_id")
        String providerId
) {
}
