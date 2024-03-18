package com.malak.security.config;


import com.malak.security.auditing.ApplicationAuditAware;
import com.malak.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
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
}
