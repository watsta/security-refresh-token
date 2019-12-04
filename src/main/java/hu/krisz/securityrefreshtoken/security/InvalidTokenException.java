package hu.krisz.securityrefreshtoken.security;

/**
 * Indicates that the provided token was invalid.
 *
 * @author krisztian.toth on 4-12-2019
 */
public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(String message) {
        super(message);
    }
}
