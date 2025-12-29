package com.nhnacademy._vidiaauth.exception.handler;

import com.nhnacademy._vidiaauth.dto.ApiResponse;
import com.nhnacademy._vidiaauth.exception.AuthErrorCode;
import com.nhnacademy._vidiaauth.exception.BaseException;
import com.nhnacademy._vidiaauth.jwt.JweUtil;
import com.nhnacademy._vidiaauth.jwt.JwtUtil;
import com.nhnacademy._vidiaauth.repository.TokenService;
import com.nhnacademy._vidiaauth.service.ReissueService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "payco.client-id=test-client-id",
        "payco.client-secret=test-secret"
})
class GlobalExceptionHandlerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    ReissueService reissueService;

    @MockitoBean
    TokenService tokenService;

    @MockitoBean
    JwtUtil jwtUtil;

    @MockitoBean
    JweUtil jweUtil;

    @Test
    @WithMockUser
    void handleBaseExceptionShouldReturnCustomErrorResponse() throws Exception {
        mockMvc.perform(get("/test/base-exception"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.header.resultCode").value(404))
                .andExpect(jsonPath("$.header.errorCode").value("U001"));
    }

    @Test
    @WithMockUser
    void handleExceptionShouldReturnInternalServerError() throws Exception {
        mockMvc.perform(get("/test/general-exception"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.header.isSuccessful").value(false))
                .andExpect(jsonPath("$.header.resultCode").value(500))
                .andExpect(jsonPath("$.header.resultMessage").value("서버 오류가 발생했습니다."))
                .andExpect(jsonPath("$.header.errorCode").value("INTERNAL_SERVER_ERROR"));
    }

    @RestController
    static class TestController {

        static class TestBaseException extends BaseException {
            public TestBaseException() {
                super(AuthErrorCode.FOR_TEST_NOT_FOUND);
            }
        }

        @GetMapping("/test/base-exception")
        public void throwBaseException() {
            throw new TestBaseException();
        }

        @GetMapping("/test/general-exception")
        public void throwGeneralException() {
            throw new RuntimeException("일반 오류 발생");
        }
    }
}
