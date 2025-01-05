package org.bbiak.skeleton_user.Domain.User.Service;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import lombok.Data;
import org.apache.coyote.Response;
import org.bbiak.skeleton_user.Domain.User.DTO.Response.ReissueTokenResponse;
import org.bbiak.skeleton_user.Domain.User.Entity.Refresh;
import org.bbiak.skeleton_user.Domain.User.Repository.RefreshRepository;
import org.bbiak.skeleton_user.Global.JWT.JWTUtil;
import org.bbiak.skeleton_user.Global.Security.Filter.LoginFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.net.http.HttpResponse;
import java.util.Date;

@Service
@Data
public class ReissueService {

    @Autowired
    private final JWTUtil jwtUtil;
    @Autowired
    private final RefreshRepository refreshRepository;

    public ReissueTokenResponse reissue(String refresh){
        try{
            jwtUtil.isExpired(refresh);
        }catch(ExpiredJwtException e){
            throw new IllegalArgumentException("Refresh 토큰이 파기 되었습니다.");
        }

        String category = jwtUtil.getCategory(refresh);
        if(!category.equals("refresh")){
            throw new IllegalArgumentException("잘못된 토큰입니다.");
        }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        String access = jwtUtil.createJwt("access",username,role,600000L);
        String newRefresh = jwtUtil.createJwt("refresh",username,role,86400000L);

        return ReissueTokenResponse.builder()
                .access(access)
                .refresh(newRefresh)
                .build();

    }

    // reissue시에 쿠키를 재생성하는 메소드
    public Cookie createCookie(String key,String value){
        Cookie cookie = new Cookie(key,value);
        cookie.setMaxAge(24*60*60);
        cookie.setHttpOnly(true);
        return cookie;
    }

    public void deleteRefresh(String refresh){

        refreshRepository.deleteByRefresh(refresh);
    }

    // 새로운 refresh 토큰을 repository에 저장하는 메소드
    public void addRefreshEntity(String username,String refresh,Long expiredMs){


            Date date = new Date(System.currentTimeMillis()+expiredMs);

            Refresh refreshEntity = Refresh.builder()
                    .username(username)
                    .refresh(refresh)
                    .expiration(date.toString())
                    .build();

            refreshRepository.save(refreshEntity);

    }

}
