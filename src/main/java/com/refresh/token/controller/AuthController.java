package com.refresh.token.controller;

import antlr.Token;
import com.refresh.token.exception.TokenRefreshException;
import com.refresh.token.model.ERole;
import com.refresh.token.model.RefreshToken;
import com.refresh.token.model.Role;
import com.refresh.token.model.User;
import com.refresh.token.payloads.request.TokenRefreshRequest;
import com.refresh.token.payloads.response.JwtResponse;
import com.refresh.token.payloads.request.LoginRequest;
import com.refresh.token.payloads.response.MessageResponse;
import com.refresh.token.payloads.request.SignupRequest;
import com.refresh.token.payloads.response.TokenRefreshResponse;
import com.refresh.token.repo.RoleRepo;
import com.refresh.token.repo.UserRepo;
import com.refresh.token.security.UserDetailsImpl;
import com.refresh.token.service.RefreshTokenService;
import com.refresh.token.service.impl.LogoutService;
import com.refresh.token.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
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
    private LogoutService logoutService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        refreshTokenService.deleteByUserId(userDetails.getId());
        RefreshToken refreshToken=refreshTokenService.createRefreshToken(userDetails.getId());


        return ResponseEntity.ok(new JwtResponse(jwt,
               refreshToken.getToken(),
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }
    @PostMapping("/refreshtoken")
    ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest  tokenRefreshRequest){
       String requestRefreshToken=tokenRefreshRequest.getRefreshToken();

       return refreshTokenService.findByToken(requestRefreshToken)
               .map(refreshTokenService::verifyExpiration)
               .map(RefreshToken::getUser)
               .map(user -> {
                   String token=jwtUtils.generateTokenFromUsername(user.getUsername());
                   return ResponseEntity.ok(new TokenRefreshResponse(token,requestRefreshToken));
               })
               .orElseThrow(()->new TokenRefreshException(requestRefreshToken,"Refresh token is not in database!"));
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
        logoutService.logout(principal);
        return ResponseEntity.status(HttpStatus.OK).body("Logout successfully!!!!");
    }

}

