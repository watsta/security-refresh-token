package hu.krisz.securityrefreshtoken.security;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Processes a form submission which includes a refresh token.
 *
 * @author krisztian.toth on 5-12-2019
 */
public class RefreshTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    /**
     * The name of the parameter which stores the refresh token.
     */
    private static final String REFRESH_TOKEN_PARAMETER = "refresh_token";

    public RefreshTokenAuthenticationFilter(RequestMatcher requestMatcher) {
        super(requestMatcher);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        var refreshTokenValue = request.getParameter(REFRESH_TOKEN_PARAMETER);
        if (refreshTokenValue == null) {
            refreshTokenValue = "NONE_PROVIDED";
        } else {
            refreshTokenValue = refreshTokenValue.trim();
        }
        var refreshToken = new RefreshTokenAuthentication(refreshTokenValue, null);
        return this.getAuthenticationManager().authenticate(refreshToken);
    }
}
