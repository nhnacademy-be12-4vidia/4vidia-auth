package com.nhnacademy._vidiaauth.service;

import com.nhnacademy._vidiaauth.dto.PaycoMemberResponse;
import com.nhnacademy._vidiaauth.dto.PaycoTokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PaycoAuthServiceTest {

    @Mock
    private RestClient restClient;

    @Mock
    private RestClient.RequestBodyUriSpec requestBodyUriSpec;

    @Mock
    private RestClient.RequestBodySpec requestBodySpec;

    @Mock
    private RestClient.ResponseSpec responseSpec;

    @InjectMocks
    private PaycoAuthService paycoAuthService;

    @BeforeEach
    void setUp() {
        // @Value 필드 값 주입
        ReflectionTestUtils.setField(paycoAuthService, "clientId", "test-client-id");
        ReflectionTestUtils.setField(paycoAuthService, "secretKey", "test-secret-key");
        ReflectionTestUtils.setField(paycoAuthService, "redirectUri", "http://localhost/callback");
    }

    @Test
    @DisplayName("Payco 리다이렉트 URL 생성 성공")
    void redirectToPayco_success() {
        // when
        String redirectUrl = paycoAuthService.redirectToPayco();

        // then
        assertThat(redirectUrl)
                .contains("https://id.payco.com/oauth2.0/authorize")
                .contains("client_id=test-client-id")
                .contains("redirect_uri=")
                .contains("serviceProviderCode=FRIENDS");
    }

    @Test
    @DisplayName("Payco Access Token 발급 요청 성공")
    void getAccessToken_success() {
        // given
        PaycoTokenResponse expectedResponse = new PaycoTokenResponse("access-token", "secret", "refresh", "Bearer", "3600");

        // RestClient Chain Mocking
        when(restClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(anyString())).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_FORM_URLENCODED)).thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(Object.class))).thenReturn(requestBodySpec); // MultiValueMap
        when(requestBodySpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.body(PaycoTokenResponse.class)).thenReturn(expectedResponse);

        // when
        PaycoTokenResponse result = paycoAuthService.getAccessToken("test-code");

        // then
        assertThat(result).isNotNull();
        assertThat(result.getAccessToken()).isEqualTo("access-token");

        // Verify: 정확한 URL로 요청했는지 검증
        verify(requestBodyUriSpec).uri("https://id.payco.com/oauth2.0/token");
    }

    @Test
    @DisplayName("Payco 회원 정보 조회 요청 성공")
    void getMemberInfo_success() {
        // given
        String accessToken = "test-access-token";
        PaycoMemberResponse expectedResponse = new PaycoMemberResponse(
                new PaycoMemberResponse.PaycoData(
                        new PaycoMemberResponse.PaycoMember("payco-id-123")
                )
        );

        // RestClient Chain Mocking
        when(restClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(anyString())).thenReturn(requestBodySpec);

        // header()는 메서드 체이닝에서 자기 자신(RequestBodySpec)을 반환하므로 이를 처리
        when(requestBodySpec.header(anyString(), anyString())).thenReturn(requestBodySpec);

        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(Map.class))).thenReturn(requestBodySpec);
        when(requestBodySpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.body(PaycoMemberResponse.class)).thenReturn(expectedResponse);

        // when
        PaycoMemberResponse result = paycoAuthService.getMemberInfo(accessToken);

        // then
        assertThat(result).isNotNull();
        assertThat(result.getData().getMember().getIdNo()).isEqualTo("payco-id-123");

        // Verify: 헤더에 client_id와 access_token이 제대로 들어갔는지 검증
        verify(requestBodySpec).header("client_id", "test-client-id");
        verify(requestBodySpec).header("access_token", accessToken);
        // Verify: 정확한 URL로 요청했는지 검증
        verify(requestBodyUriSpec).uri("https://apis-payco.krp.toastoven.net/payco/friends/find_member_v2.json");
    }
}