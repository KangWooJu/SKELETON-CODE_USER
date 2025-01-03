package org.bbiak.skeleton_user.Domain.User.DTO.Request;

import lombok.Data;

@Data
public class SignUpRequest {

    private String username;
    private String password;
    private String nickname;

}
