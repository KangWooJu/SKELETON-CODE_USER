package org.bbiak.skeleton_user.Global.Security.Config;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.bbiak.skeleton_user.Global.Security.Filter.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@Data
public class SecurityConfig {

    //AuthenticationManager Bean 등록
    private final AuthenticationConfiguration authenticationConfiguration;
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        http
                .csrf((auth)->auth.disable()); // csrf 사용 X
        http
                .formLogin((auth)->auth.disable()); // Form로그인 사용 X
        http
                .httpBasic((auth)->auth.disable()); // http Basic 인증사용 X
        http
                .authorizeHttpRequests((auth)->auth
                        .requestMatchers("/login","/").permitAll()
                        .anyRequest().authenticated()); // 기본 설정 : 로그인 , 회원 가입 페이지만 가능하게 설정

        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration)), UsernamePasswordAuthenticationFilter.class); // 필터추가1 : usernamePasswordAuthenticationFilter

        http
                .sessionManagement((session)->session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // HttpSecurity 객체에서 세션 관리 설정을 담당하는 메서드
        // 세션 생성 정책으로 STATELESS 설정



        return http.build();
    }
}
