package com.malak.security.user;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.malak.security.token.Token;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder  // build my object in easy way using design patter builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "_user") // to avoid ambiguity with postgres user
public class User implements UserDetails {

    @Id
    @GeneratedValue // auto genereted // auto incremented
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;
    private boolean mfaEnabled; //flag
    private String secret;

    @Enumerated(EnumType.STRING)// use it string or ordinal 1 0
    private Role role;

    @OneToMany(mappedBy = "user")
    @JsonManagedReference
    private List<Token> tokens;

    // should return list of roles ==> add enum role
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // return List.of(new SimpleGrantedAuthority(role.name()));
        return role.getAuthorities();
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    //get password is not overriten because of lombok

}
