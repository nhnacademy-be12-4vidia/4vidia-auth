package com.nhnacademy._vidiaauth.client;

import com.nhnacademy._vidiaauth.dto.OAuth2UserDto;
import com.nhnacademy._vidiaauth.dto.PaycoUserRequest;
import com.nhnacademy._vidiaauth.dto.UserInfoResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "4vidia-bookstore-service")
public interface UserClient {

    @GetMapping("/users") // 기존 "/my/users"
    UserInfoResponse getUserByEmail(@RequestParam String email);

    @PostMapping("/auth/payco/find-or-create")
    OAuth2UserDto findOrCreateByPaycoId(@RequestBody PaycoUserRequest paycoUserRequest);
}
