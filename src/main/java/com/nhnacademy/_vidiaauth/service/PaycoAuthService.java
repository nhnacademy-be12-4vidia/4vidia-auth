package com.nhnacademy._vidiaauth.service;

import com.nhnacademy._vidiaauth.dto.PaycoMemberResponse;
import com.nhnacademy._vidiaauth.dto.PaycoTokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class PaycoAuthService {
    private final String PAYCO_TOKEN_URL = "https://id.payco.com/oauth2.0/token";
    private final String PAYCO_USERINFO_URL = "https://apis-payco.krp.toastoven.net/payco/friends/find_member_v2.json";
    private final RestClient restClient;
    @Value("${payco.client-id}")
    private String clientId;
    @Value("${payco.client-secret}")
    private String secretKey;
    @Value("${payco.redirect-uri}")
    private String redirectUri;

    public PaycoTokenResponse getAccessToken(String code) {

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", clientId);
        params.add("client_secret", secretKey);
        params.add("code", code);



        PaycoTokenResponse response = restClient.post()
                .uri(PAYCO_TOKEN_URL)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(params)
                .retrieve()
                .body(PaycoTokenResponse.class);
        return response;
    }

    public String redirectToPayco() {
        return "https://id.payco.com/oauth2.0/authorize" +
                        "?response_type=code" +
                        "&client_id=" + clientId +
                        "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8) +
                        "&serviceProviderCode=FRIENDS" +
                        "&userLocale=ko_KR";
    }


    public PaycoMemberResponse getMemberInfo(String accessToken) {
        Map<String, String> body = Map.of();

        PaycoMemberResponse result = restClient.post()
                .uri(PAYCO_USERINFO_URL)
                .header("client_id", clientId)
                .header("access_token", accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .body(PaycoMemberResponse.class);
        return result;
    }
}
