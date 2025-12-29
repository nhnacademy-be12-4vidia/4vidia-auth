package com.nhnacademy._vidiaauth.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class RestClientConfigTest {

    @Autowired
    RestClient restClient;

    @Test
    void restClientBeanShouldBeCreated() {
        assertThat(restClient).isNotNull();
    }

    @Test
    void restClientShouldBeInstanceOfRestClient() {
        assertThat(restClient).isInstanceOf(RestClient.class);
    }
}
