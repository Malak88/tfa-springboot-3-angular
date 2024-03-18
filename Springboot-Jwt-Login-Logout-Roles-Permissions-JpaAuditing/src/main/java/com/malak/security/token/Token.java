package com.malak.security.token;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.malak.security.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder  // build my object in easy way using design patter builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
//@Table(name = "_token1")
public class Token {

    @Id
    @GeneratedValue
    public Integer id;

    @Column(unique = true)
    public String token;

    @Enumerated(EnumType.STRING)
    public TokenType tokenType ;

    public boolean revoked;

    public boolean expired;

    @ManyToOne
    @JoinColumn(name = "user_id")
    @JsonBackReference
    public User user;
}
