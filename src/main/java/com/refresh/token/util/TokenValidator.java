package com.refresh.token.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;

import java.util.HashMap;
import java.util.Map;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class TokenValidator {
    Boolean tokenExpired = true;
    @Value("${trekkieAbi.app.jwtSecret}")
    private String jwtKey;
    public boolean isTokenValid(String token) throws Exception {
        validateToken(token);
        return tokenExpired;
    }

    public Map<String,String> getExtractedData(String token) throws Exception {
        return validateToken(token);
    }

    private Map<String, String> validateToken (String token) throws Exception{
        try {
            Claims claims = Jwts.parser().setSigningKey(jwtKey)
                    .parseClaimsJws(token).getBody();
            tokenExpired = false;
            return getClaimsInMap(claims);
        } catch (ExpiredJwtException ex) {

            return getClaimsInMap(ex.getClaims());
        } catch (Exception e) {
            throw new Exception(e);
        }
    }
    private Map<String,String> getClaimsInMap(Claims claims) {
        Map<String,String> expectedMap = new HashMap<>();
        claims.entrySet().stream().forEach(entry -> expectedMap.put(entry.getKey(),entry.getValue().toString()));
        return expectedMap;
    }
}
