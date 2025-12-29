package com.nhnacademy._vidiaauth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class PaycoMemberResponse {
    private PaycoData data;

    @Getter
    @AllArgsConstructor
    public static class PaycoData{
        private PaycoMember member;
    }
    @Getter
    @AllArgsConstructor
    public static class PaycoMember{
        private String idNo;
    }
}
