package hu.krisz.securityrefreshtoken.security.token.refresh;

import java.util.Optional;

/**
 * An interface for storing and accessing refresh tokens.
 *
 * @author krisztian.toth on 5-12-2019
 */
public interface RefreshTokenStore {

    /**
     * Stores the refresh token.
     *
     * @param refreshToken the refresh token
     */
    void storeRefreshToken(RefreshToken refreshToken);

    /**
     * Gets the refresh token.
     *
     * @param tokenValue the refresh token
     * @return an {@link Optional}<{@link RefreshToken}>
     */
    Optional<RefreshToken> getRefreshToken(String tokenValue);

    /**
     * Removes the refresh token.
     *
     * @param refreshToken the refresh token
     */
    void removeRefreshToken(RefreshToken refreshToken);
}
