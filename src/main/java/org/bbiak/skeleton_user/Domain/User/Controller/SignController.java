package org.bbiak.skeleton_user.Domain.User.Controller;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.bbiak.skeleton_user.Domain.User.DTO.Request.SignUpRequest;
import org.bbiak.skeleton_user.Domain.User.DTO.Response.SignUpResponse;
import org.bbiak.skeleton_user.Domain.User.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

@RestController
public class SignController {

    private final UserService userService;

    @Autowired
    public SignController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<SignUpResponse> signUp(@RequestBody SignUpRequest signUpRequest){
        SignUpResponse signUpResponse = userService.signUp(signUpRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(signUpResponse);
    }




}
