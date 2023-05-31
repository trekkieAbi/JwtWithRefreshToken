package com.refresh.token.filter;

import com.refresh.token.constant.AppConstant;
import com.refresh.token.model.RefreshToken;
import com.refresh.token.model.User;
import com.refresh.token.payloads.request.LoginRequest;
import com.refresh.token.payloads.response.MessageResponse;
import com.refresh.token.repo.RefreshTokenRepo;
import com.refresh.token.repo.UserRepo;
import com.refresh.token.service.RefreshTokenService;
import com.refresh.token.service.impl.UserDetailsServiceImpl;
import com.refresh.token.util.JwtUtils;
import com.refresh.token.util.TokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.time.Instant;
import java.util.Arrays;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private RefreshTokenRepo refreshTokenRepo;
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private TokenValidator tokenValidator;
    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        HttpEntity<ResponseEntity> entity = new HttpEntity<>(headers);

        try {
            String jwt = parseJwt(request);
            if(tokenValidator.isTokenValid(jwt)){
                RefreshToken refreshToken=parseRefreshToken(request);
                Principal principal=(Principal) SecurityContextHolder.getContext().getAuthentication();
                if(refreshToken.getExpiryDate().compareTo(Instant.now())>=0) {
               /* if(refreshToken==null){//validate whether refresh token is received from cookies or not....

                    if(refreshToken==null){//validate whether the loggedInUser has a refresh token or not....
                       refreshToken=refreshTokenService.createRefreshToken(loggedInUser.getId());
                    }
                }*/
                    if(validateLoggedInUserWithUserInToken(principal,refreshToken)){
                        restTemplate.exchange(AppConstant.REFRESH_TOKEN_URL, HttpMethod.POST,entity,HttpServletRequest.class);
                        setUserAuthenticationInContextHolder(jwt,request);
                    }else {
                        throw new RuntimeException("Logged in user id and refresh token user id does not match!!!");
                    }



              }else{
                    if(validateLoggedInUserWithUserInToken(principal,refreshToken)){
                        LoginRequest loginRequest=new LoginRequest();
                        loginRequest.setUsername(userRepo.findByUsername(principal.getName()).get().getUsername());
                        loginRequest.setPassword(userRepo.findByUsername(principal.getName()).get().getPassword());
                        restTemplate.exchange(AppConstant.LOGIN_URL,HttpMethod.POST,entity,LoginRequest.class);
                        setUserAuthenticationInContextHolder(jwt,request);
                    }

                }

            }
            else if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                setUserAuthenticationInContextHolder(jwt,request);

            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        Principal principal=request.getUserPrincipal();

        String jwt=jwtUtils.getJwtFromCookies(request);
        return jwt;
    }

    private RefreshToken parseRefreshToken(HttpServletRequest request){
        String refreshToken=jwtUtils.getJwtRefreshFromCookies(request);
        return refreshTokenRepo.findByToken(refreshToken).get();
    }

    private void setUserAuthenticationInContextHolder(String jwt,HttpServletRequest request){
        String username = jwtUtils.getUserNameFromJwtToken(jwt);

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
    private boolean validateLoggedInUserWithUserInToken(Principal principal,RefreshToken refreshToken){
        Boolean status=false;
        User loggedInUser = userRepo.findByUsername(principal.getName()).get();
        if (loggedInUser.getId().equals(refreshToken.getUser().getId())) {//validate whether refresh token's user id  recieved from cookie match with the loggedInUser id
        status=true;

        }
        return status;
    }




}
