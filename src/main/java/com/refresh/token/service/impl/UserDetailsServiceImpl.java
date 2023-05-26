package com.refresh.token.service.impl;

import com.refresh.token.model.User;
import com.refresh.token.repo.UserRepo;
import com.refresh.token.security.UserDetailsImpl;
import com.refresh.token.service.UserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserRepo userRepo;
    @Transactional
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user=userRepo.findByUsername(username)
                .orElseThrow(()->new UsernameNotFoundException("User not found with username: "+username));


        return UserDetailsImpl.build(user);
    }
}
