package org.bbiak.skeleton_user.Domain.User.Controller;

import lombok.Data;
import org.bbiak.skeleton_user.Domain.User.DTO.Request.SignUpRequest;
import org.bbiak.skeleton_user.Domain.User.DTO.Response.SignUpResponse;
import org.bbiak.skeleton_user.Domain.User.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

@RestController
@Data
public class SignController {

    @Autowired
    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<SignUpResponse> signUp(@RequestBody SignUpRequest signUpRequest){
        SignUpResponse signUpResponse = userService.signUp(signUpRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(signUpResponse);
    }

    @GetMapping("/test")
    public String tests(){
        return "testGood for Authentication";
    }

    @DeleteMapping("/signout")
    public ResponseEntity<?> signOut(@RequestHeader("access")String access){
        userService.signOut(access);
        return ResponseEntity.ok("User 정보가 삭제되었습니다.");
    }



}
