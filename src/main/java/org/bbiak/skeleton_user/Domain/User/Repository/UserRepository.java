package org.bbiak.skeleton_user.Domain.User.Repository;

import java.util.*;
import org.bbiak.skeleton_user.Domain.User.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findById(Long id);
    Optional<User> findbyUsername(String username);



}
