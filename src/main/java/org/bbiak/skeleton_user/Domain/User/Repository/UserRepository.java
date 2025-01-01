package org.bbiak.skeleton_user.Domain.User.Repository;



import org.springframework.data.jpa.repository.JpaRepository;
import org.bbiak.skeleton_user.Domain.User.Entity.User;
import java.util.*;


public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findByUsername(String username);
    Optional<User> findByNickname(String nickname);

}
