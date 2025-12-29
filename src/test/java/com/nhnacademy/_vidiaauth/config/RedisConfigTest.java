package com.nhnacademy._vidiaauth.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class RedisConfigTest {

    @Autowired
    ApplicationContext applicationContext;

    @Autowired
    RedisConnectionFactory redisConnectionFactory;

    @Autowired
    RedisTemplate<String, String> redisTemplate;

    @Test
    void redisConnectionFactoryBeanShouldBeCreated() {
        assertThat(redisConnectionFactory).isNotNull();
    }

    @Test
    void redisTemplateBeanShouldBeCreated() {
        assertThat(redisTemplate).isNotNull();
    }

    @Test
    void redisTemplateShouldUseStringKeySerializer() {
        assertThat(redisTemplate.getKeySerializer())
                .isInstanceOf(StringRedisSerializer.class);
    }

    @Test
    void redisTemplateShouldUseJsonValueSerializer() {
        assertThat(redisTemplate.getValueSerializer())
                .isInstanceOf(GenericJackson2JsonRedisSerializer.class);
    }
}
