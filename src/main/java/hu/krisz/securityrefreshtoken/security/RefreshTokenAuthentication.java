package hu.krisz.securityrefreshtoken.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed for a refresh token representation.
 *
 * @author krisztian.toth on 5-12-2019
 */
public class RefreshTokenAuthentication extends AbstractAuthenticationToken {
    private final String refreshToken;

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param refreshToken the refresh token
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     */
    public RefreshTokenAuthentication(String refreshToken, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.refreshToken = refreshToken;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return refreshToken;
    }
}
