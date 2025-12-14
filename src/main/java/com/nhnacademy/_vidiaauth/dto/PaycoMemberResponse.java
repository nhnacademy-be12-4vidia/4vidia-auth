package com.nhnacademy._vidiaauth.dto;

import lombok.Getter;

@Getter
public class PaycoMemberResponse {
    private PaycoData data;

    @Getter
    public static class PaycoData{
        private PaycoMember member;
    }
    @Getter
    public static class PaycoMember{
        private String idNo;
    }
}
