package com.nhnacademy._vidiaauth.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;

@Component
public class JweUtil {

    private final SecretKey secretKey;

    public JweUtil(@Value("${jwe.secret}") String secret) {
        // AES 256 비밀키 생성
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "AES");
    }

    // JWT → JWE 암호화
    public String encrypt(String jwt) throws JOSEException {
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
        Payload payload = new Payload(jwt);
        JWEObject jweObject = new JWEObject(header, payload);

        DirectEncrypter encrypter = new DirectEncrypter(secretKey);
        jweObject.encrypt(encrypter);

        return jweObject.serialize();
    }

    // JWE → JWT 복호화
    public String decrypt(String jwe) throws ParseException, JOSEException {
        JWEObject jweObject = JWEObject.parse(jwe);
        DirectDecrypter decrypter = new DirectDecrypter(secretKey);
        jweObject.decrypt(decrypter);

        return jweObject.getPayload().toString(); // JWT 원본 반환
    }

}
