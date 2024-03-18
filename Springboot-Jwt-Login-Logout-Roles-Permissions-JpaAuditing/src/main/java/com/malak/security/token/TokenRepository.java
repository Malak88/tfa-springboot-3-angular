package com.malak.security.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    //need 2 methods

    //1 get all valid tokens for specific user id
    @Query("""
      select t from Token t inner join User u on t.user.id = u.id
      where u.id = :userId and (t.expired = false or t.revoked = false)
      """)
    List<Token> findAllValidTokensByUser(Integer userId);

    //2 find token by token itself
    Optional<Token> findByToken(String Token);

}
