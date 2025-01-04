package org.bbiak.skeleton_user.Domain.User.Controller;


import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import org.bbiak.skeleton_user.Domain.User.DTO.Response.ReissueTokenResponse;
import org.bbiak.skeleton_user.Domain.User.Service.ReissueService;
import org.bbiak.skeleton_user.Global.JWT.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.*;

@RestController
@Data
public class ReissueController {

    @Autowired
    private final JWTUtil jwtUtil;
    @Autowired
    private final ReissueService reissueService;

    // Refresh 토큰을 재발급 하는 URL
    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response){

        String refresh =null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies){
            if (cookie.getName().equals("refresh")){
                refresh = cookie.getValue();
            }
        }

       if (refresh == null){
           return new ResponseEntity<>("Refresh 토큰이 없습니다.",HttpStatus.BAD_REQUEST);
       }

       try{
           ReissueTokenResponse reissueTokenResponse = reissueService.reissue(refresh);
           String newAccessToken = reissueTokenResponse.getAccess();
           String newRefreshToken = reissueTokenResponse.getRefresh();


           response.setHeader("access",newAccessToken);
           response.addCookie(reissueService.createCookie("refresh",newRefreshToken));

           return new ResponseEntity<>("새로운 Access 토큰이 발급되었습니다.",HttpStatus.OK);

       } catch(IllegalArgumentException e){
           return new ResponseEntity<>(e.getMessage(),HttpStatus.BAD_REQUEST);
       }
    }
}
