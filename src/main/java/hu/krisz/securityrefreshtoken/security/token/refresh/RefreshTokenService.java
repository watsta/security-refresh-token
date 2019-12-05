package hu.krisz.securityrefreshtoken.security.token.refresh;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Service to manage refresh tokens.
 *
 * @author krisztian.toth on 5-12-2019
 */
public class RefreshTokenService {
    private final RefreshTokenStore refreshTokenStore;
    private final Integer refreshTokenValidity;

    public RefreshTokenService(RefreshTokenStore refreshTokenStore, Integer refreshTokenValidity) {
        this.refreshTokenStore = refreshTokenStore;
        this.refreshTokenValidity = refreshTokenValidity;
    }

    public RefreshToken generateRefreshToken(String userId) {
        return new RefreshToken(userId, generateRefreshToken(), generateExpiryDate());
    }

    public RefreshToken generateRefreshToken(String userId, Instant expiryDate) {
        return new RefreshToken(userId, generateRefreshToken(), expiryDate);
    }

    public void storeRefreshToken(RefreshToken refreshToken) {
        refreshTokenStore.storeRefreshToken(refreshToken);
    }

    public Optional<RefreshToken> getRefreshToken(String refreshTokenValue) {
        return refreshTokenStore.getRefreshToken(refreshTokenValue);
    }

    public void removeRefreshToken(RefreshToken refreshToken) {
        refreshTokenStore.removeRefreshToken(refreshToken);
    }

    private String generateRefreshToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private Instant generateExpiryDate() {
        return Instant.now().plusSeconds(refreshTokenValidity);
    }
}
