package hu.krisz.securityrefreshtoken.security.token;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Objects;

/**
 * Wrapper for information parsed from the JWT token.
 *
 * @author krisztian.toth on 4-12-2019
 */
public class UserTokenInformation {
    private final String userId;
    private final Collection<? extends GrantedAuthority> authorities;

    public UserTokenInformation(String userId, Collection<? extends GrantedAuthority> authorities) {
        this.userId = userId;
        this.authorities = authorities;
    }

    public String getUserId() {
        return userId;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserTokenInformation that = (UserTokenInformation) o;
        return Objects.equals(userId, that.userId) &&
                Objects.equals(authorities, that.authorities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, authorities);
    }

    @Override
    public String toString() {
        return "UserTokenInformation{" +
                "userId='" + userId + '\'' +
                ", authorities=" + authorities +
                '}';
    }
}
