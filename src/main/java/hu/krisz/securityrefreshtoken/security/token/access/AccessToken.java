package hu.krisz.securityrefreshtoken.security.token.access;

import java.time.Instant;
import java.util.Objects;

public class AccessToken {
    private final String tokenValue;
    private final Instant expiryDate;

    public AccessToken(String tokenValue, Instant expiryDate) {
        this.tokenValue = tokenValue;
        this.expiryDate = expiryDate;
    }

    public long expiresIn() {
        return ((expiryDate.toEpochMilli() - System.currentTimeMillis()) / 1000);
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AccessToken that = (AccessToken) o;
        return Objects.equals(tokenValue, that.tokenValue) &&
                Objects.equals(expiryDate, that.expiryDate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tokenValue, expiryDate);
    }

    @Override
    public String toString() {
        return "AccessToken{" +
                "tokenValue='" + tokenValue + '\'' +
                ", expiryDate=" + expiryDate +
                '}';
    }

}
