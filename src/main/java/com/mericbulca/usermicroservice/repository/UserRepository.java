package com.mericbulca.usermicroservice.repository;

import com.mericbulca.usermicroservice.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {


    public Optional<User> findUserByEmail(String email);
    public Optional<User> findUserByUsername(String username);

}
