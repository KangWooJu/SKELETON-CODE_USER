package org.bbiak.skeleton_user.Domain.User.Controller;

import lombok.Data;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.*;

@RestController
@Data
public class UserController {

    @GetMapping("/profile")
    public ResponseEntity<?> showProfile(@RequestHeader("access")String access){
        // 수정중
        return ResponseEntity.ok("asdasd");
    }
}
