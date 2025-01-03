package org.bbiak.skeleton_user.Global.Security.Filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bbiak.skeleton_user.Domain.User.Entity.CustomUserDetails;
import org.bbiak.skeleton_user.Global.JWT.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.bbiak.skeleton_user.Domain.User.Entity.User;

import java.io.IOException;
import java.util.Collections;

@Data
@Slf4j
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authorization = request.getHeader("Authorization");
        if(authorization==null){
            log.info("첫 로그인 실행");
        }

        // 헤더의 Authorization 검사
        if((authorization==null)||(!authorization.startsWith("Bearer"))){

            filterChain.doFilter(request,response);
            return;
        }

        log.info("Authorization 실행중---");
        String token = authorization.split(" ")[1]; // Bearer 부분 제거 후 순수 토큰만 획득

        if(jwtUtil.isExpired(token)){
            log.info("Token 유지시간이 종료되었습니다. ( 파기 )");
            filterChain.doFilter(request,response);
            return;
        }

        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        User user = User.builder()
                .username(username)
                .password("temppassword")
                .role(role)
                .nickname("tempNickname")
                .build();

        // CustomUserDetails 객체 생성 ( user 객체 삽입 )
        CustomUserDetails customUserDetails = new CustomUserDetails(user);

        // Authentication 객체 생성 ( CustomUserDetails 객체 삽입 )
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails
                ,null
                ,customUserDetails.getAuthorities());

        // 시큐리티 컨테이너에 등록 -> 인증된 사용자로 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request,response);
    }


}
