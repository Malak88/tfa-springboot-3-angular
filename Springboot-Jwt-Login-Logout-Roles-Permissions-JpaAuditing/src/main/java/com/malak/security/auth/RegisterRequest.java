package com.malak.security.auth;

import com.malak.security.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    private String firstname;
    private String lastname;
    private String email;
    private String password;
    private Role role; // add that in role permission to make it dynamic //
                        // we have to think about the way we need to manage roles !!
                        // it could be different
    private boolean mfaEnabled;
}
