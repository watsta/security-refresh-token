package hu.krisz.securityrefreshtoken.security.token.refresh;

import java.time.Instant;
import java.util.Objects;

public class RefreshToken {
    private final String userId;
    private final String tokenValue;
    private final Instant expiryDate;

    public RefreshToken(String userId, String tokenValue, Instant expiryDate) {
        this.userId = userId;
        this.tokenValue = tokenValue;
        this.expiryDate = expiryDate;
    }

    public long expiresIn() {
        return ((expiryDate.toEpochMilli() - System.currentTimeMillis()) / 1000);
    }

    public boolean isExpired() {
        return expiresIn() <= 0;
    }

    public String getUserId() {
        return userId;
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
        RefreshToken that = (RefreshToken) o;
        return Objects.equals(userId, that.userId) &&
                Objects.equals(tokenValue, that.tokenValue) &&
                Objects.equals(expiryDate, that.expiryDate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, tokenValue, expiryDate);
    }

    @Override
    public String toString() {
        return "RefreshToken{" +
                "userId='" + userId + '\'' +
                ", tokenValue='" + tokenValue + '\'' +
                ", expiryDate=" + expiryDate +
                '}';
    }
}
