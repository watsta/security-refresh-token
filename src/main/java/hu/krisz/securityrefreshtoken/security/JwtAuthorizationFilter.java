package hu.krisz.securityrefreshtoken.security;

import hu.krisz.securityrefreshtoken.security.token.UserTokenInformation;
import hu.krisz.securityrefreshtoken.security.token.access.AccessTokenService;
import io.jsonwebtoken.JwtException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter to handle authorization based on the provided JWT token in
 * the authorization header.
 *
 * @author krisztian.toth on 4-12-2019
 */
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

    private final AccessTokenService accessTokenService;

    public JwtAuthorizationFilter(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        var authHeader = request.getHeader("Authorization");
        if (authHeader == null) {
            throw new InvalidTokenException("invalid token");
        }
        var token = authHeader.replace("Bearer ", "");

        UserTokenInformation parsedToken;
        try {
            parsedToken = accessTokenService.parse(token);
        } catch (JwtException e) {
            LOGGER.info("could not parse token: {}", token, e);
            throw e;
        }

        var authentication = new UsernamePasswordAuthenticationToken(
                parsedToken.getUserId(),
                null,
                parsedToken.getAuthorities()
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}
