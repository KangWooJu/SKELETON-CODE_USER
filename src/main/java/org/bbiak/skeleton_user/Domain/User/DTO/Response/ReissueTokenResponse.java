package org.bbiak.skeleton_user.Domain.User.DTO.Response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ReissueTokenResponse {

    private String access;
    private String refresh;
}
