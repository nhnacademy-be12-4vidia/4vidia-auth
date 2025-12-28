package com.nhnacademy._vidiaauth.exception.handler;

import org.springframework.http.HttpStatus;

public interface ErrorCodeProvider {
    HttpStatus getStatus();
    String getCode();
    String getMessage();
    String getName();
}
