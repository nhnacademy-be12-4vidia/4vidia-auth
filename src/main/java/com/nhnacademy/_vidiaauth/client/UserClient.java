package com.nhnacademy._vidiaauth.client;

import com.nhnacademy._vidiaauth.dto.UserInfoResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "4vidia-bookstore-service")
public interface UserClient {
    @GetMapping("/my/users")
    UserInfoResponse getUserByEmail(@RequestParam String email);
}
