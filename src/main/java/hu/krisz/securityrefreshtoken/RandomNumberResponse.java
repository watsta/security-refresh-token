package hu.krisz.securityrefreshtoken;

import java.util.Objects;

public class RandomNumberResponse {
    private final int randomNumber;

    public RandomNumberResponse(int randomNumber) {
        this.randomNumber = randomNumber;
    }

    public int getRandomNumber() {
        return randomNumber;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RandomNumberResponse that = (RandomNumberResponse) o;
        return randomNumber == that.randomNumber;
    }

    @Override
    public int hashCode() {
        return Objects.hash(randomNumber);
    }

    @Override
    public String toString() {
        return "RandomNumberResponse{" +
                "randomNumber=" + randomNumber +
                '}';
    }
}
