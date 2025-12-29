package com.nhnacademy._vidiaauth.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JweUtilTest {

    private JweUtil jweUtil;

    @BeforeEach
    void setUp() {
        // 32 bytes (AES-256)
        String secret = "0123456789abcdef0123456789abcdef";
        jweUtil = new JweUtil(secret);
    }

    @Test
    void encryptAndDecryptShouldReturnOriginalJwt() throws Exception {
        String originalJwt = "test.jwt.token.value";

        String encrypted = jweUtil.encrypt(originalJwt);
        String decrypted = jweUtil.decrypt(encrypted);

        assertThat(encrypted).isNotNull();
        assertThat(decrypted).isEqualTo(originalJwt);
    }
}
