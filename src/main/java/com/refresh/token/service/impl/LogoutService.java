package com.refresh.token.service.impl;

import com.refresh.token.model.RefreshToken;
import com.refresh.token.model.User;
import com.refresh.token.repo.RefreshTokenRepo;
import com.refresh.token.repo.UserRepo;
import com.refresh.token.security.UserDetailsImpl;
import com.refresh.token.service.RefreshTokenService;
import com.refresh.token.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
public class LogoutService  {
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private RefreshTokenRepo refreshTokenRepo;
    @Autowired
    private JwtUtils jwtUtils;



    public void logout(Principal principal) {
        UserDetailsImpl userDetails=(UserDetailsImpl) principal;
       Optional<User> loggedInUser=userRepo.findByUsername(principal.getName());
        Optional<RefreshToken>  refreshToken=refreshTokenRepo.findByUser(loggedInUser.get());
        if(refreshToken.get().getExpiryDate().compareTo(Instant.now())<0){
            refreshTokenRepo.delete(refreshToken.get());
        }
    }
}
