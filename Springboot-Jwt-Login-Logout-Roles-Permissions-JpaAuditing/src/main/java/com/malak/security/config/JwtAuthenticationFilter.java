package com.malak.security.config;

import com.malak.security.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException; 

// this need to be manager bean : service, bean or repository, component
@Component
@RequiredArgsConstructor // constructor with any final field declared
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService; // final to implement our own fetch username
    // do a class to implement this interface  give it service or component anno
    // to  beacome a mange bean
    // soo spring will be able to inject it
    // do that with a fancy way == in appconfig
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(
           @NonNull HttpServletRequest request,
           @NonNull  HttpServletResponse response,
           @NonNull  FilterChain filterChain   //chain of responsibilty of design patter call next
    ) throws ServletException, IOException {

        //check if jwt exist
        // extract header  bearer token
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        // header exist ?? or start with other than bearer // car token tjrs start with bearer+" "
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;   // if null not continue the execution of rest code
        }

        // extrat token from this header
        jwt = authHeader.substring(7); //count bearer with space

        // call userdetail service to extract username
        // from jwt token ==> jwtservice
        userEmail = jwtService.extractUsername(jwt);

        //==> do the jwtservice

        //finishing validation process
        // and user not yet auhtnticated/connected
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // check if we have user in the DB !!
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // ==> di implem in the appConfig : userdetailsservice
            //double check if token is revoked
            Boolean isTokenValid = tokenRepository.findByToken(jwt)
                    .map(token -> !token.isExpired() && !token.isRevoked())
                    .orElse(false);

            if(jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
                // update the security context and send  the request to the dispatcher servelet
                // create object of type username, password , token auth
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,  // we don't have credantials yet
                        userDetails.getAuthorities()
                );
                // give it more details: enforce token with details of our request
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // final step update the security context holder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // after it does filter
        filterChain.doFilter(request,response);
        //==> Add security config
        // which config to use in order to make all this works ( in blue )
        //==> binding ==> use the filter, because it's not yet used
    }
}
