package hu.krisz.securityrefreshtoken.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import hu.krisz.securityrefreshtoken.security.token.TokenResponse;
import hu.krisz.securityrefreshtoken.security.token.UserTokenInformation;
import hu.krisz.securityrefreshtoken.security.token.access.AccessTokenService;
import hu.krisz.securityrefreshtoken.security.token.refresh.RefreshTokenService;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.time.Instant;

/**
 * Handles successful token refresh request.
 *
 * @author krisztian.toth on 5-12-2019
 */
public class TokenRefreshSuccessHandler implements AuthenticationSuccessHandler {
    private final AccessTokenService accessTokenService;
    private final RefreshTokenService refreshTokenService;
    private final UserDetailsService userDetailsService;
    private final ObjectMapper objectMapper;

    public TokenRefreshSuccessHandler(AccessTokenService accessTokenService,
                                      RefreshTokenService refreshTokenService,
                                      UserDetailsService userDetailsService,
                                      ObjectMapper objectMapper) {
        this.accessTokenService = accessTokenService;
        this.refreshTokenService = refreshTokenService;
        this.userDetailsService = userDetailsService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        var refreshTokenValue = (String) authentication.getPrincipal();
        var refreshToken = refreshTokenService.getRefreshToken(refreshTokenValue)
                .orElseThrow(() -> new ServletException("refresh token not found in store after successful authentication"));

        var userDetails = userDetailsService.loadUserByUsername(refreshToken.getUserId());
        var tokenResponse = generateNewTokens(userDetails, refreshToken.getExpiryDate());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().print(objectMapper.writeValueAsString(tokenResponse));
        response.getWriter().flush();
    }

    private TokenResponse generateNewTokens(UserDetails userDetails, Instant expiryDate) {
        var newRefreshToken = refreshTokenService.generateRefreshToken(userDetails.getUsername(), expiryDate);
        refreshTokenService.storeRefreshToken(newRefreshToken);
        var userTokenInformation = new UserTokenInformation(userDetails.getUsername(), userDetails.getAuthorities());
        var newAccessToken = accessTokenService.create(userTokenInformation);
        return new TokenResponse(newRefreshToken.getTokenValue(), newAccessToken.getTokenValue(), newAccessToken.expiresIn());
    }
}
