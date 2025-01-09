package org.bbiak.skeleton_user.Domain.User.DTO.Request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignUpRequest {

    private String username;
    private String password;
    private String nickname;

}
