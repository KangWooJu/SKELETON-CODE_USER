package org.bbiak.skeleton_user.Domain.User.Service;

import jdk.jfr.DataAmount;
import lombok.Data;
import org.bbiak.skeleton_user.Domain.User.DTO.Request.SignUpRequest;
import org.bbiak.skeleton_user.Domain.User.Repository.UserRepository;
import org.bbiak.skeleton_user.Global.Exception.CustomException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.*;

@Data
@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public SignUpRequest signUp(SignUpRequest signUpRequest) throws Exception{

       if(userRepository.findbyUsername(signUpRequest.getUsername()).isPresent()){
           throw new CustomException();
       }

    }


}
