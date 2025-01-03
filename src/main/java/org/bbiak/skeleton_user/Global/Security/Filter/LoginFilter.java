package org.bbiak.skeleton_user.Global.Security.Filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bbiak.skeleton_user.Domain.User.Entity.CustomUserDetails;
import org.bbiak.skeleton_user.Domain.User.Entity.User;
import org.bbiak.skeleton_user.Global.JWT.JWTUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.*;



@Data
@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        try {

            // 1st. 클라이언트 요청에서 username , password 를 JSON에서  추출하기
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, String> loginData = objectMapper.readValue(request.getInputStream(), Map.class);
            // username , password 두가지 String 타입 변수를 받아온다.

            String username = loginData.get("username");
            String password = loginData.get("password");

            // 2nd. 스프링 시큐리티에서 username과 password를 토큰에 담기
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

            // 3rd. 검증을 위해서 AuthenticationManager 에서 검증을 위해 전달
            return authenticationManager.authenticate(authToken);

        } catch (IOException e) {
            throw new AuthenticationServiceException("잘못된 형식의 로그인 입력입니다.");
        }
    }

    // 로그인 성공시 실행하는 메소드 ( JWT 발급 )
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authentication) {

        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        // CustomUserDetails 객체 가져오기 -> getPrincipal()로 인증된 사용자를 캐스팅

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        // 사용자 권한을 추출
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        // 이터레이터를 통해 객체 권한 반환
        GrantedAuthority auth = iterator.next();
        // 맨 처음 권한을 가져오기

        String role = auth.getAuthority();
        String access = jwtUtil.createJwt("access",username,role,600000L);
        String refresh = jwtUtil.createJwt("refresh",username,role,86400000L);

        // SecurityContext에 이미 인증 정보가 등록되어 있는지 확인 -> 첫 로그인일 경우 컨테이너에 등록
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        if (existingAuth == null || !existingAuth.isAuthenticated()) {
            log.info("SecurityContext에 인증 정보를 등록합니다.");

            // SecurityContext에 인증 정보 등록
            User user = User.builder()
                    .username(username)
                    .password("temppassword") // 실제 비밀번호는 저장하지 않음
                    .role(role)
                    .nickname("tempNickname")
                    .build();

            CustomUserDetails newCustomUserDetails = new CustomUserDetails(user);
            Authentication authToken = new UsernamePasswordAuthenticationToken(
                    newCustomUserDetails, null, newCustomUserDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authToken);
        } else {
            log.info("SecurityContext에 이미 인증 정보가 등록되어 있습니다.");
        }


        response.setHeader("access",access); // 헤더에 access Token 추가 ( Authorization 으로 Bearer를 감싸서 보내기 )
        response.addCookie(createCookie("refresh",refresh)); // 쿠키에 refresh 토큰 생성
    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException failed) {

        response.setStatus(401);
    }

    private Cookie createCookie(String key,String value){

        Cookie cookie = new Cookie(key,value);
        cookie.setMaxAge(24*60*60); // 쿠키 생명주기 설정
        cookie.setHttpOnly(true);

        return cookie;
    }
}
