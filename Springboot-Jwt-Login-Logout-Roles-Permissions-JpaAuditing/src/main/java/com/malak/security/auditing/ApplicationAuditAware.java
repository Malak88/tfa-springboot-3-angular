package com.malak.security.auditing;

import com.malak.security.user.User;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class ApplicationAuditAware implements AuditorAware<Integer> { // !!! how to choose the type ? ==> what to track if id integer if email string
    @Override
    public Optional<Integer> getCurrentAuditor() {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null ||
                !authentication.isAuthenticated() || //user not authenticated
                authentication instanceof AnonymousAuthenticationToken
        ) {
            return Optional.empty();

        }

        User userPrinciple  = (User) authentication.getPrincipal();
        return Optional.ofNullable(userPrinciple.getId());

    }
}
