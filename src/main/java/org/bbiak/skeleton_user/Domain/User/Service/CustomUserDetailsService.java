package org.bbiak.skeleton_user.Domain.User.Service;

import lombok.Data;
import org.bbiak.skeleton_user.Domain.User.Entity.CustomUserDetails;
import org.bbiak.skeleton_user.Domain.User.Entity.User;
import org.bbiak.skeleton_user.Domain.User.Repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Data
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
        Optional<User> optionalUser = userRepository.findByUsername(username);
        User user = optionalUser.orElseThrow(() -> new RuntimeException("User not found"));
        return new CustomUserDetails(user);

    }
}
