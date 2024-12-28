package org.bbiak.skeleton_user.Domain.User.DTO.Response;

import lombok.Data;

@Data
public class SignUpResponse {

    private Long id;
    private String username;
    private String nickname;
}
