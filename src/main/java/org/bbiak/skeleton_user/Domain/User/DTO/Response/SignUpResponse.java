package org.bbiak.skeleton_user.Domain.User.DTO.Response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SignUpResponse {

    private Long id;
    private String username;
    private String nickname;
}
