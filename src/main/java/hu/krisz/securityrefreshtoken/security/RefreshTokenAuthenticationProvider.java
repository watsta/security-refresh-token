package hu.krisz.securityrefreshtoken.security;

import hu.krisz.securityrefreshtoken.security.token.refresh.RefreshTokenService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * An implementation of {@link AuthenticationProvider} that checks whether the refresh token
 * is present in our persistent store.
 *
 * @author krisztian.toth on 5-12-2019
 */
public class RefreshTokenAuthenticationProvider implements AuthenticationProvider {
    private final RefreshTokenService refreshTokenService;

    public RefreshTokenAuthenticationProvider(RefreshTokenService refreshTokenService) {
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        var refreshToken = refreshTokenService.getRefreshToken((String) authentication.getPrincipal())
                .orElseThrow(() -> new RefreshTokenExpiredException("invalid refresh token"));

        if (refreshToken.isExpired()) {
            refreshTokenService.removeRefreshToken(refreshToken);
            throw new RefreshTokenExpiredException("refresh token expired");
        }

        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return RefreshTokenAuthentication.class.isAssignableFrom(authentication);
    }
}
