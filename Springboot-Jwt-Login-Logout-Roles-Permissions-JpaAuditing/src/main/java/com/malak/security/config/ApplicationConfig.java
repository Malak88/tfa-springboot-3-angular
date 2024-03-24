package com.malak.security.config;


import com.malak.security.auditing.ApplicationAuditAware;
import com.malak.security.user.UserRepository;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.ORIGIN;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;
import static org.springframework.web.bind.annotation.RequestMethod.PATCH;

// will hold all app config such as bean ..
@Configuration //at app start app spring will pick up this class and inject all beans delarated here
@RequiredArgsConstructor // in case we need to inject sthg
public class ApplicationConfig {

    //create bean userDetailsService

    private  final UserRepository userRepository;

    //from jwtAuthFilter
    @Bean // bean is always public
    public UserDetailsService userDetailsService() {
        //lambda expression
        return username -> userRepository.findByEmail(username) //return optional we need to add orElse if not founded !!
                .orElseThrow(() -> new UsernameNotFoundException("User not found")); //exception
    }

    // ==> go finish filter

    //coming from Security config
    // authenticationProvider() = DAO data access object to fetch the user details + password ..
    // ( many implem)
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider  authProvider = new DaoAuthenticationProvider();
        //specify 2 properties
        // 1 which details service to use in order to fetch info about user
        authProvider.setUserDetailsService(userDetailsService());
        // 2 which password encoder used !!
        authProvider.setPasswordEncoder(passwordEncoder()); //create bean for password encoder
        return authProvider;
    }

    @Bean
    public AuditorAware<Integer> auditorAware() {
        return new ApplicationAuditAware();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // last step to finish appConfig
    //AuthManager = have mth to authenticate user with username + password

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    //end
    // provide endpoints == controller

    //CORS pronlem Solution
    @Bean
    public CorsFilter corsFilter() {
      final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      final CorsConfiguration config = new CorsConfiguration();
      config.setAllowCredentials(true);
      config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
      config.setAllowedHeaders(Arrays.asList(
              ORIGIN,
              CONTENT_TYPE,
              ACCEPT,
              AUTHORIZATION
      ));
      config.setAllowedMethods(Arrays.asList(
              GET.name(),
              POST.name(),
              DELETE.name(),
              PUT.name(),
              PATCH.name()
      ));
      source.registerCorsConfiguration("/**", config);
      return new CorsFilter(source);
    }
}
