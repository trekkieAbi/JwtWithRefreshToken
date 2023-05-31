package com.refresh.token.controller;

import com.refresh.token.exception.TokenRefreshException;
import com.refresh.token.model.ERole;
import com.refresh.token.model.RefreshToken;
import com.refresh.token.model.Role;
import com.refresh.token.model.User;
import com.refresh.token.payloads.request.TokenRefreshRequest;
import com.refresh.token.payloads.request.LoginRequest;
import com.refresh.token.payloads.response.JwtResponse;
import com.refresh.token.payloads.response.MessageResponse;
import com.refresh.token.payloads.request.SignupRequest;
import com.refresh.token.payloads.response.TokenRefreshResponse;
import com.refresh.token.repo.RefreshTokenRepo;
import com.refresh.token.repo.RoleRepo;
import com.refresh.token.repo.UserRepo;
import com.refresh.token.security.UserDetailsImpl;
import com.refresh.token.service.RefreshTokenService;
import com.refresh.token.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.security.Principal;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepo userRepo;

    @Autowired
    RoleRepo roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private RefreshTokenRepo refreshTokenRepo;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
      //  Authentication authentication1=SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        ResponseCookie jwtCookie=jwtUtils.generateJwtCookie(userDetails);
        //String jwt = jwtUtils.generateJwtToken(userDetails);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        refreshTokenService.deleteByUserId(userDetails.getId());
        RefreshToken refreshToken=refreshTokenService.createRefreshToken(userDetails.getId());
        ResponseCookie jwtRefreshCookie=jwtUtils.generateRefreshJwtCookie(refreshToken.getToken());


        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE,jwtRefreshCookie.toString())
                .body( new JwtResponse(userDetails.getId(),
                        userDetails.getUsername()
                        ,userDetails.getEmail()
                        ,roles
                        ));
    }
    @PostMapping("/refreshtoken")
    ResponseEntity<MessageResponse> refreshToken(HttpServletRequest request){
       String requestRefreshToken=jwtUtils.getJwtRefreshFromCookies(request);
       if(requestRefreshToken!=null && (requestRefreshToken.length())>0) {
           return refreshTokenService.findByToken(requestRefreshToken)
                   .map(refreshTokenService::verifyExpiration)
                   .map(RefreshToken::getUser)
                   .map(user -> {
                       //String token=jwtUtils.generateTokenFromUsername(user.getUsername());
                       ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(user);
                       return ResponseEntity.ok()
                               .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                               .body(new MessageResponse("Token is refreshed successfully!!!"));
                   })
                   .orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Refresh token is not in database!"));
       }
       return ResponseEntity.badRequest().body(new MessageResponse("Refresh token is empty!!!"));
    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepo.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepo.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepo.save(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/logout")
    ResponseEntity<?> logout(Principal principal){
       Object principle=SecurityContextHolder.getContext().getAuthentication().getPrincipal();
       if(principle.toString()!="anonymousUser"){
           Long userId=((UserDetailsImpl) principle).getId();
           RefreshToken refreshToken=refreshTokenRepo.findByUser(userRepo.findByUsername(principal.getName()).get()).get();
           if(refreshToken.getExpiryDate().compareTo(Instant.now())<0){
               refreshTokenService.deleteByUserId(userId);
           }
       }

       ResponseCookie jwtCookie=jwtUtils.getCleanJwtCookie();
       ResponseCookie jwtRefreshCookie=jwtUtils.getCleanJwtRefreshCookie();

       return ResponseEntity.ok()
               .header(HttpHeaders.SET_COOKIE,jwtCookie.toString())
               .header(HttpHeaders.SET_COOKIE,jwtRefreshCookie.toString())
               .body(new MessageResponse("You've been signout!"));


    }

}

