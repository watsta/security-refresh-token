package hu.krisz.securityrefreshtoken.security;

import hu.krisz.securityrefreshtoken.security.token.access.AccessTokenService;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
    private final AccessTokenService accessTokenService;

    public JwtAuthorizationFilter(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        var token = request.getHeader("Authorization");
        if (token == null) {
            throw new InvalidTokenException("invalid token");
        }
        var parsedToken = accessTokenService.parse(token);
        var authentication = new UsernamePasswordAuthenticationToken(
                parsedToken.getUserId(),
                null,
                parsedToken.getAuthorities()
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}
