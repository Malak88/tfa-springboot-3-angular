package com.malak.security.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.malak.security.config.JwtService;
import com.malak.security.tfa.TwoFactorAuthenticationService;
import com.malak.security.token.Token;
import com.malak.security.token.TokenRepository;
import com.malak.security.token.TokenType;
import com.malak.security.user.Role;
import com.malak.security.user.User;
import com.malak.security.user.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TwoFactorAuthenticationService tfaService;

    public AuthenticationResponse register(RegisterRequest request) {
        //create user +save it in database + return generated jwt token
        //create user
        User user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) //encode password ,inject password encoder
                .role(Role.ADMIN) //static role
                .mfaEnabled(request.isMfaEnabled())
                .build();
        // if MFA enabled --> Generate Secret
        if (request.isMfaEnabled()) {
            user.setSecret(tfaService.generateNewSecret());
        }
        // save it in database
        User savedUser = userRepository.save(user);
        // return generated jwt token + inject jwtservice
        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        // persist Token in DB + user
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
              .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .mfaEnabled(user.isMfaEnabled())
                .secretImageUri(tfaService.generateQrCodeImageUri(user.getSecret()))
              .build();
    }

    // authen manager bean has mtd = authenticate( username+password )
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        ); //user authenticated
        // find the user to genrate the token
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(); // + optional
        if (user.isMfaEnabled()) {
            return AuthenticationResponse.builder()
                    .accessToken("")
                    .refreshToken("")
                    .mfaEnabled(true)
                    .build();
        }
        // return generated jwt token + inject jwtservice
        String  jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        revokedAllUserTokens(user);
        saveUserToken(user,jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .mfaEnabled(false)
                .build();
    }

    private void saveUserToken(User user, String jwtToken) {
        Token token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }
    private void revokedAllUserTokens(User user){

        List<Token> validUserTokens = tokenRepository.
                findAllValidTokensByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        //check if jwt exist
        // extract header  bearer token
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        // header exist ?? or start with other than bearer // car token tjrs start with bearer+" "
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            return;   // if null not continue the execution of rest code
        }

        // extrat token from this header
        refreshToken = authHeader.substring(7); //count bearer with space

        // call userdetail service to extract username
        // from jwt token ==> jwtservice
        userEmail = jwtService.extractUsername(refreshToken);

        //==> do the jwtservice

        //finishing validation process
        // and user not yet authenticated/connected
        if(userEmail != null) {
            // check if we have user in the DB !!
            var user = this.userRepository.findByEmail(userEmail)
                    .orElseThrow();
            // ==> di implem in the appConfig : userdetailsservice
            //double check if token is revoked

            if (jwtService.isTokenValid(refreshToken, user) ) {

                //generate new access token  1 day + keep the refresh token 7days!!
                var accessToken = jwtService.generateToken(user);
                revokedAllUserTokens(user);
                saveUserToken(user,accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .mfaEnabled(false)
                        .build();
                // how to get a return from a void method
                // using
                new ObjectMapper().writeValue(response.getOutputStream(),authResponse);
                //will be body of the response
            }
        }
    }

    public AuthenticationResponse verifyCode(
            VerificationRequest verificationRequest
    ) {
        User user = userRepository
                .findByEmail(verificationRequest.getEmail())
                .orElseThrow(() -> new EntityNotFoundException(
                        String.format("No user found with %S", verificationRequest.getEmail()))
                );
        if (tfaService.isOtpNotValid(user.getSecret(), verificationRequest.getCode())) {

            throw new BadCredentialsException("Code is not correct");
        }
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .mfaEnabled(user.isMfaEnabled())
                .build();
    }
}
