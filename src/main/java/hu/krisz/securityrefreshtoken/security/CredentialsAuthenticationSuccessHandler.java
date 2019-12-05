package hu.krisz.securityrefreshtoken.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import hu.krisz.securityrefreshtoken.security.token.TokenResponse;
import hu.krisz.securityrefreshtoken.security.token.UserTokenInformation;
import hu.krisz.securityrefreshtoken.security.token.access.AccessTokenService;
import hu.krisz.securityrefreshtoken.security.token.refresh.RefreshTokenService;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

/**
 * Custom Authentication success handler when authenticating with user credentials.
 *
 * @author krisztian.toth on 4-12-2019
 */
public class CredentialsAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final AccessTokenService accessTokenService;
    private final RefreshTokenService refreshTokenService;
    private final ObjectMapper objectMapper;

    public CredentialsAuthenticationSuccessHandler(AccessTokenService accessTokenService,
                                                   RefreshTokenService refreshTokenService,
                                                   ObjectMapper objectMapper) {
        this.accessTokenService = accessTokenService;
        this.refreshTokenService = refreshTokenService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {
        var userDetails = (UserDetails) authentication.getPrincipal();

        var userTokenInformation = new UserTokenInformation(userDetails.getUsername(), userDetails.getAuthorities());
        var accessToken = accessTokenService.create(userTokenInformation);
        var refreshToken = refreshTokenService.generateRefreshToken(userDetails.getUsername());
        refreshTokenService.storeRefreshToken(refreshToken);
        var tokenResponse = new TokenResponse(refreshToken.getTokenValue(), accessToken.getTokenValue(), accessToken.expiresIn());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().print(objectMapper.writeValueAsString(tokenResponse));
        response.getWriter().flush();
    }
}
