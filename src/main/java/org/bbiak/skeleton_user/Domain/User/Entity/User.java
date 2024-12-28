package org.bbiak.skeleton_user.Domain.User.Entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.*;

@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name="USER")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="user_id")
    private Long id; // 고유 넘버

    @Column(name="user_username",nullable = false,unique = true)
    private String username; // 로그인 아이디

    @Column(name="user_password",nullable = false)
    private String password; // 비밀번호

    @Column(name="user_nickname",nullable = false,unique = true)
    private String nickname; // 서비스 닉네임

    @Builder
    public User(String username,String password,String nickname){
        this.username = username;
        this.password = password;
        this.nickname = nickname;
    }
}
