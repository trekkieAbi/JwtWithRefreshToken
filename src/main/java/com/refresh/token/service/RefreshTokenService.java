package com.refresh.token.service;

import com.refresh.token.model.RefreshToken;

import java.util.Optional;

public interface RefreshTokenService {
    Optional<RefreshToken> findByToken(String token);
    RefreshToken createRefreshToken(Long userId);
    RefreshToken verifyExpiration(RefreshToken refreshToken);

    Integer deleteByUserId(Long userId);
}
