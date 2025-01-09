package org.bbiak.skeleton_user.Global.Security.Filter;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bbiak.skeleton_user.Domain.User.Repository.RefreshRepository;
import org.bbiak.skeleton_user.Global.JWT.JWTUtil;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@Data
@AllArgsConstructor
@Slf4j
public class CustomLogoutFilter extends GenericFilterBean {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;


    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain)
            throws IOException,ServletException{
        doFilter((HttpServletRequest) request,(HttpServletResponse) response,chain); // 형변환을 위한 오버로드
    }

    // Overload Method
    private void doFilter(HttpServletRequest request,
                          HttpServletResponse response,
                          FilterChain chain)
            throws IOException, ServletException {

        String requestURI = request.getRequestURI();
        String requestMethod = request.getMethod();

        // URI 검증
        if(!requestURI.matches("^\\/logout$")){

            chain.doFilter(request,response);
            return;
        }
        // method 검증
        if(!requestMethod.equals("POST")){

            chain.doFilter(request,response);
            return;

        }
        // refresh 토큰 받아오기
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            log.info("Cookies가 비어 있습니다.");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        for (Cookie cookie : cookies) {

            if (cookie.getName().equals("refresh")) {

                refresh = cookie.getValue();
            }
        }

        //refresh 토큰이 비엇는지 확인하기
        if (refresh == null) {

            log.info("Refresh 토큰이 비어있습니다.");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // refresh 토큰 만료여부 확인
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {

            log.info("Refresh 토큰이 만료되었습니다.");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        String category = jwtUtil.getCategory(refresh);
        // refresh가 맞는지 확인
        if (!category.equals("refresh")) {

            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {

            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //로그아웃 진행
        //Refresh 토큰 DB에서 제거
        refreshRepository.deleteByRefresh(refresh);

        //Refresh 토큰 Cookie 값 0
        Cookie cookie = new Cookie("refresh", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);

    }
}
