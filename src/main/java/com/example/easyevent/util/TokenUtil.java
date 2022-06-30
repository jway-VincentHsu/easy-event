package com.example.easyevent.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;

public class TokenUtil {

    static final long MILLI_SECONDS_IN_HOUR = 1*60*60*1000;
    static final String ISSUER = "easyevent";
    static final String USER_ID = "userId";
    static Algorithm algorithm = Algorithm.HMAC256("mysecretkey");

    public static String signToken(Integer userID, int expirationInHour){
        String token = JWT.create()
                .withIssuer(ISSUER)
                .withClaim(USER_ID,userID)
                .withExpiresAt(new Date(System.currentTimeMillis()+expirationInHour*MILLI_SECONDS_IN_HOUR))
                .sign(algorithm);

        return token;
    }

    public static Integer verifyToken(String token){
        JWTVerifier verifier = JWT.require(algorithm).withIssuer(ISSUER).build();
        DecodedJWT jwt = verifier.verify(token);
        Integer userId = jwt.getClaim(USER_ID).asInt();
        return userId;
    }
}
