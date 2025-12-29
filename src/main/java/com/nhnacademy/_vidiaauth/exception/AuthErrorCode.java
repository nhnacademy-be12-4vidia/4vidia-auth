package com.nhnacademy._vidiaauth.exception;

import com.nhnacademy._vidiaauth.exception.handler.ErrorCodeProvider;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;

@AllArgsConstructor
public enum AuthErrorCode implements ErrorCodeProvider {

    FOR_TEST_NOT_FOUND(HttpStatus.NOT_FOUND, "U001", "찾을 수 없습니다.");

    private final HttpStatus status;
    private final String code;
    private final String message;

    @Override
    public HttpStatus getStatus() {
        return status;
    }

    @Override
    public String getCode() {
        return code;
    }

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public String getName() {
        return this.name();
    }

}
