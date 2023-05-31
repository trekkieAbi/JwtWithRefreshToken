package com.refresh.token.util;

import com.refresh.token.model.User;
import com.refresh.token.security.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${trekkieAbi.app.jwtSecret}")
    private String jwtSecret;

    @Value("${trekkieAbi.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${trekkieAbi.app.jwtCookieName}")
    private String jwtCookie;
    @Value("${trekkieAbi.app.jwtRefreshCookieName}")
    private String jwtRefreshCookie;


    public ResponseCookie generateJwtCookie(UserDetailsImpl userDetails){
        String jwt=generateTokenFromUsername(userDetails.getUsername());
        Date date=getExpirationDateFromToken(jwt);
        System.out.println(date.toString());
        return generateCookie(jwtCookie,jwt,"/api");
    }

    public ResponseCookie generateJwtCookie(User user){
        String jwt=generateTokenFromUsername(user.getUsername());
        return generateCookie(jwtCookie,jwt,"/api");
    }

    public ResponseCookie generateRefreshJwtCookie(String refreshToken){
        return generateCookie(jwtRefreshCookie,refreshToken,"/api");
    }

    public Boolean isTokenExpired(String token){
        Date expiration=this.getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }


    public String getJwtFromCookies(HttpServletRequest request){
        return getCookieValueByName(request,jwtCookie);
    }

    public String getJwtRefreshFromCookies(HttpServletRequest request){
        return getCookieValueByName(request,jwtRefreshCookie);
    }
    public ResponseCookie getCleanJwtCookie(){
        ResponseCookie cookie=ResponseCookie.from(jwtCookie,null).path("/api").build();
        return cookie;
    }

    public ResponseCookie getCleanJwtRefreshCookie(){
        ResponseCookie cookie=ResponseCookie.from(jwtRefreshCookie,null).path("/api/auth/refreshtoken").build();
        return cookie;
    }



    private String getCookieValueByName(HttpServletRequest request, String jwtCookie) {
        Cookie cookie= WebUtils.getCookie(request,jwtCookie);
        if(cookie!=null){
            return cookie.getValue();
        }else {
            return null;
        }
    }

    private ResponseCookie generateCookie(String name, String value, String path) {
        ResponseCookie responseCookie= ResponseCookie.from(name, value).path(path).maxAge(24*60*60).httpOnly(true).build();
       return responseCookie;
    }



    public String generateJwtToken(UserDetailsImpl userDetails) {
        return generateTokenFromUsername(userDetails.getUsername());
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }


    public String generateTokenFromUsername(String username){
        return Jwts.builder().setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime()+jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512,jwtSecret)
                .compact();

    }


    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    private Claims getAllClaimsFromToken(String token){
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        Claims claims = this.getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);

    }

    public Date getExpirationDateFromToken(String token) {
        return this.getClaimFromToken(token, Claims::getExpiration);
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }


}
