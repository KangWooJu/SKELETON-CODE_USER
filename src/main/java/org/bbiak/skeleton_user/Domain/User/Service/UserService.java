package org.bbiak.skeleton_user.Domain.User.Service;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bbiak.skeleton_user.Domain.User.DTO.Request.NameDuplicationRequest;
import org.bbiak.skeleton_user.Domain.User.DTO.Request.SignUpRequest;
import org.bbiak.skeleton_user.Domain.User.DTO.Response.SignUpResponse;
import org.bbiak.skeleton_user.Domain.User.Entity.User;
import org.bbiak.skeleton_user.Domain.User.Repository.UserRepository;
import org.bbiak.skeleton_user.Global.Exception.CustomException;
import org.bbiak.skeleton_user.Global.JWT.JWTUtil;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Data
@Slf4j
@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JWTUtil jwtUtil;

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

    // 유저 정보 삭제 ( 회원 탈퇴 ) 메소드
    @Transactional
    public String signOut(String access){

        String username = jwtUtil.getUsername(access);
        userRepository.findByUsername(username)
                .map(user->{
                    userRepository.delete(user);
                    return "DB에서 유저 정보를 삭제하였습니다.";
                })
                .orElse("유저 정보를 찾을 수 없습니다.");
        return "Deleted OK";
    }

    public String checkDupication(NameDuplicationRequest nameDuplicationRequest){

        String username = nameDuplicationRequest.getName();
        userRepository.findByUsername(username)
                      .ifPresent(user -> {
                        throw new UsernameAlreadyException(username); // 커스텀 예외 생성 필요
                      });


        return
    }

}
