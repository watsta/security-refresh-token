package hu.krisz.securityrefreshtoken.security.token.access;

import io.jsonwebtoken.Jwts;
import org.springframework.security.core.GrantedAuthority;

import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class AccessTokenService {
    private final Key secretKey;
    private final Integer accessTokenExpirationSeconds;

    public AccessTokenService(Key secretKey, Integer accessTokenExpirationSeconds) {
        this.secretKey = secretKey;
        this.accessTokenExpirationSeconds = accessTokenExpirationSeconds;
    }

    public AccessToken create(String userId, Collection<? extends GrantedAuthority> grantedAuthorities) {
        var expiryDate = calculateExpiryDate();
        var tokenValue = Jwts.builder()
                .signWith(secretKey)
                .setIssuer("issuer")
                .setAudience("audience")
                .setSubject(userId)
                .setExpiration(expiryDate)
                .claim("roles", getRolesFrom(grantedAuthorities))
                .compact();
        return new AccessToken(tokenValue, expiryDate.toInstant());
    }

    private Date calculateExpiryDate() {
        return new Date(System.currentTimeMillis() + accessTokenExpirationSeconds * 1000);
    }

    private List<String> getRolesFrom(Collection<? extends GrantedAuthority> grantedAuthorities) {
        return grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    }
}
