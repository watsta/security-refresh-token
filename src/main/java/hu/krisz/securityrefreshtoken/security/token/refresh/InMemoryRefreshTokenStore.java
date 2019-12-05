package hu.krisz.securityrefreshtoken.security.token.refresh;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory implementation of {@link RefreshTokenStore}.
 *
 * @author krisztian.toth on 5-12-2019
 */
public class InMemoryRefreshTokenStore implements RefreshTokenStore {
    private ConcurrentMap<String, RefreshToken> refreshTokenValueToRefreshToken = new ConcurrentHashMap<>();
    private ConcurrentMap<String, RefreshToken> userIdToRefreshToken = new ConcurrentHashMap<>();

    @Override
    public void storeRefreshToken(RefreshToken refreshToken) {
        var existingRefreshToken = userIdToRefreshToken.get(refreshToken.getUserId());
        if (existingRefreshToken != null) {
            refreshTokenValueToRefreshToken.remove(existingRefreshToken.getTokenValue());
        }
        refreshTokenValueToRefreshToken.put(refreshToken.getTokenValue(), refreshToken);
        userIdToRefreshToken.put(refreshToken.getUserId(), refreshToken);
    }

    @Override
    public Optional<RefreshToken> getRefreshToken(String tokenValue) {
        return Optional.ofNullable(refreshTokenValueToRefreshToken.get(tokenValue));
    }

    @Override
    public void removeRefreshToken(RefreshToken refreshToken) {
        refreshTokenValueToRefreshToken.remove(refreshToken.getTokenValue());
        userIdToRefreshToken.remove(refreshToken.getUserId());
    }
}
