package com.mericbulca.usermicroservice.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {

    @Query(value = """
    SELECT t from Token t INNER JOIN user u\s
    ON t.user.id = u.id\s
    where u.id = :id and (t.expired = false or t.revoked = false)
    """)
    List<Token> findAllValidTokenByUser(Long id);

    Optional<Token> findByToken(String token);
}
