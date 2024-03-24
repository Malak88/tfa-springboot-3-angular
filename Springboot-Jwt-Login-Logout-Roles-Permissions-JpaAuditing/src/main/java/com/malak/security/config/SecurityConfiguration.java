package com.malak.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.malak.security.user.Permission.*;
import static com.malak.security.user.Role.ADMIN;
import static com.malak.security.user.Role.MANAGER;
import static org.springframework.http.HttpMethod.*;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity  // to use @PreAutorized in controllers instead of the commented block
public class SecurityConfiguration {

    // at app start up, spring security will try to look for bean of type security filterchain
    // security filterchain = responsible of configuring all http securinf of our app
    private static final String[] WHITE_LIST_URL = {"/api/v1/auth/**",
            "/v2/api-docs",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui/**",
            "/webjars/**",
            "/swagger-ui.html"};
    private final JwtAuthenticationFilter jwtAuthFilter; // final to be automatically injected by spring
    private final AuthenticationProvider authenticationProvider; // need to be implemented in appConfig class
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

       // http.csrf().disable() : deprecated
        //implement real config
        // what are url and paths we want to secure
        // white list = endpoints dont requires any token /auth ==> open e.g login, create account ..
        // 1 implemnt white list
        http
                .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(null))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        authReq -> authReq
                        .requestMatchers(WHITE_LIST_URL).permitAll()

                        .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
                                .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                                .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                                .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                                .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

                        /*.requestMatchers("/api/v1/admin/**").hasRole(ADMIN.name()) //not anyRole
                                .requestMatchers(GET, "/api/v1/admin/**").hasAuthority(ADMIN_READ.name()) // not Anyaytohrity just 1
                                .requestMatchers(POST, "/api/v1/admin/**").hasAuthority(ADMIN_CREATE.name())
                                .requestMatchers(PUT, "/api/v1/admin/**").hasAuthority(ADMIN_UPDATE.name())
                                .requestMatchers(DELETE, "/api/v1/admin/**").hasAuthority(ADMIN_DELETE.name())
*/  // we can use annotation instead
                        .anyRequest()
                                .authenticated()// configure session management
                )// every request should be authed
                // should not stroe the auth state/ session to ensure taht every request should be authenticated
                .sessionManagement(sess -> sess.sessionCreationPolicy(STATELESS)) // spring will create new session for each request
                .authenticationProvider(authenticationProvider) // which auth provider to use
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class) // use filter created before the filter called usernamepasswordauthentitication filter 1  // we check jwt before the last one 1
                .logout(( logout) ->
                        logout.logoutUrl("/api/v1/auth/logout")
                                .addLogoutHandler(logoutHandler) // binding logout service
                                .logoutSuccessHandler((request, response, authentication) ->
                                                   SecurityContextHolder.clearContext())

                )
        ; // clear our security context !!

        return http.build(); // build might throw an exception
    }
}
