package hu.krisz.securityrefreshtoken.security.token.access;

import hu.krisz.securityrefreshtoken.security.token.UserTokenInformation;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class AccessTokenService {
    private static final String ISSUER = "issuer";
    private static final String AUDIENCE = "audience";
    private final Key secretKey;
    private final Integer accessTokenExpirationSeconds;

    public AccessTokenService(Key secretKey, Integer accessTokenExpirationSeconds) {
        this.secretKey = secretKey;
        this.accessTokenExpirationSeconds = accessTokenExpirationSeconds;
    }

    public AccessToken create(UserTokenInformation userTokenInformation) {
        var expiryDate = calculateExpiryDate();
        var tokenValue = Jwts.builder()
                .signWith(secretKey)
                .setIssuer(ISSUER)
                .setAudience(AUDIENCE)
                .setSubject(userTokenInformation.getUserId())
                .setExpiration(expiryDate)
                .claim("roles", getRolesFrom(userTokenInformation.getAuthorities()))
                .compact();
        return new AccessToken(tokenValue, expiryDate.toInstant());
    }

    public UserTokenInformation parse(String tokenValue) {
        var body = Jwts.parser()
                .setSigningKey(secretKey)
                .requireIssuer(ISSUER)
                .requireAudience(AUDIENCE)
                .parseClaimsJws(tokenValue)
                .getBody();
        return new UserTokenInformation(body.getAudience(), createRolesFrom(body));
    }

    private List<String> getRolesFrom(Collection<? extends GrantedAuthority> grantedAuthorities) {
        return grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private Collection<? extends GrantedAuthority> createRolesFrom(Claims body) {
        var roles = (Collection<String>) body.get("roles");
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    private Date calculateExpiryDate() {
        return new Date(System.currentTimeMillis() + accessTokenExpirationSeconds * 1000);
    }
}
