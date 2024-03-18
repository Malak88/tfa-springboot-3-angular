package com.malak.security.config;

import com.malak.security.token.Token;
import com.malak.security.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor // incase I need to inject sthg
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        // we need to invalidate the token
        // get and extract the token from the request
        // fetch this request in the database and validate it
        //authFilter will do the job since we update our mechanism implem

        //check if jwt exist
        // extract header  bearer token
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        // header exist ?? or start with other than bearer // car token tjrs start with bearer+" "
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            return;   // if null not continue the execution of rest code
        }

        // extrat token from this header
        jwt = authHeader.substring(7); //count bearer with space
        Token storedToken = tokenRepository.findByToken(jwt)
                .orElse(null);
        if (storedToken != null) {
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            tokenRepository.save(storedToken);
            SecurityContextHolder.clearContext();
        }
    }
}
