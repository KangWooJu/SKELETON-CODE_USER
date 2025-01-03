package org.bbiak.skeleton_user.Domain.User.Service;

import lombok.Data;
import org.bbiak.skeleton_user.Domain.User.DTO.Request.SignUpRequest;
import org.bbiak.skeleton_user.Domain.User.DTO.Response.SignUpResponse;
import org.bbiak.skeleton_user.Domain.User.Entity.User;
import org.bbiak.skeleton_user.Domain.User.Repository.UserRepository;
import org.bbiak.skeleton_user.Global.Common.code.ErrorCode;
import org.bbiak.skeleton_user.Global.Exception.CustomException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Data
@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // User 생성 메소드
    @Transactional
    public SignUpResponse signUp(SignUpRequest signUpRequest) throws RuntimeException{

        if(userRepository.findByUsername(signUpRequest.getUsername()).isPresent()){
            throw new CustomException();// 예외추가 필요

        }

        if(userRepository.findByNickname(signUpRequest.getNickname()).isPresent()){
            throw new CustomException(); // 예외추가 필요
        }

        // 비밀번호 검증: null 또는 빈 값일 경우 예외 처리
        if (signUpRequest.getPassword() == null || signUpRequest.getPassword().isEmpty()) {
            throw new CustomException(); // 예외 추가 필요
        }

        String encodedPassword = bCryptPasswordEncoder.encode(signUpRequest.getPassword()); // 비밀번호 암호화하기

        // 빌더 패턴으로 User 정보 save
        User user = User.builder()
                .nickname(signUpRequest.getNickname())
                .password(encodedPassword)
                .username(signUpRequest.getUsername())
                .role("ROLE_ADMIN")
                .build();

        User savedUser = userRepository.save(user);

        return SignUpResponse.builder()
                .id(savedUser.getId())
                .nickname(savedUser.getNickname())
                .username(savedUser.getUsername())
                .build();

    }

}
