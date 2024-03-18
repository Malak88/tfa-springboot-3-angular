package com.malak.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {


    @Value("${application.security.jwt.secret-key}")
    private String secretKey;
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    //1
    //5 how to extract the username from 4
    public String extractUsername(String token) {
        // to manipualte jwt token + genration + validation ==> add dependecy in pom
        return extractClaim(token, Claims::getSubject); // subject of token = mail or username
    }

    //4 extract any single claim from token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {

        final Claims claims = extractAllClaims(token);

        return claimsResolver.apply(claims);
    }

    //8 what if I want to generate the user without extra claim, just from user details
    public String generateToken(UserDetails userDetails ) {
        return generateToken( new HashMap<>(), userDetails);
    }
    //7 genrating  the token
    public  String generateToken(
            Map<String, Object> extraClaims, // if want to pass authority or any info to store within token
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public  String generateRefreshToken(
            UserDetails userDetails
    ) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken (
            Map<String, Object> extraClaims, // if want to pass authority or any info to store within token
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())  // unique !!
                .setIssuedAt(new Date(System.currentTimeMillis())) // when this claim was created
                .setExpiration(new Date(System.currentTimeMillis()+ expiration))  // ==> calculate experation date, tokn valid or not
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); // will generate + compact the token
    }

    //9 validate token : does it belong to that user ??
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    //10 is token expired ??
    private boolean isTokenExpired(String token) {
        return extractExperation(token).before(new Date());
    }


    //6 extratcting the experation data
    private Date  extractExperation( String token ){
        return extractClaim(token, Claims::getExpiration);
    }


    //2
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    //3
    private Key getSignInKey() {  // secret =  digital sign of jwt
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // ==> go to finish filter implem
}
