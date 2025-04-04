package org.bbiak.skeleton_user.Global.JWT;

import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Jwts;
import java.util.*;


import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Component
public class JWTUtil {

    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}")String secret){
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // < 토큰을 이용한 메소드들 과정 정리 >
    // 1.JWT Parser 생성
    // 2. secretKey로 검증
    // 3. Parser를 빌드
    // 4. Token을 파싱하여 클레임 ( claims ) 생성
    // 5. payload 불러오기
    // 6. 원하는 정보 불러오기 -> 각 메소드마다 커스텀

    // Token의 페이로드에서 Username 추출하는 메소드
    public String getUsername(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("username",String.class);
    }

    // Token의 페이로드에서 role 추출하는 메소드
    public String getRole(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role",String.class);
    }


    // Token의 만료여부 확인 메소드
    public Boolean isExpired(String token){

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()
                .before(new Date());
        // before(new Date()) : 만료시간이 현재시간보다 이전인지 확인하기
    }

    public String createJwt(String category,String username,String role,Long expiredMs){

        // 1. JWT Claim에 정보 추가 ( Username , Role )
        // 2. 현재 시간을 기준으로 발행시간 설정 ( issuedAt() )
        // 3. 만료시간 관련처리 로직
        // 4. secretKey에 사인 저장 ( 필수 ! )
        // 4. JWT를 최종적으로 직렬화하여 문자열로 반환하기 ( compact() )
        return Jwts.builder()
                .claim("category",category) // 토큰의 종류 : Access or Refresh
                .claim("username",username)
                .claim("role",role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+expiredMs))
                .signWith(secretKey)
                .compact();
    }

    public String getCategory(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("category",String.class);
    }
}


