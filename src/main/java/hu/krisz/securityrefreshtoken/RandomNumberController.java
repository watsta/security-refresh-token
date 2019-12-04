package hu.krisz.securityrefreshtoken;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Random;

@ResponseBody
@RequestMapping
public class RandomNumberController {
    private final Random randomNumberGenerator;

    public RandomNumberController(Random randomNumberGenerator) {
        this.randomNumberGenerator = randomNumberGenerator;
    }

    @GetMapping("/random")
    public RandomNumberResponse getRandomNumber() {
        return new RandomNumberResponse(randomNumberGenerator.nextInt());
    }
}
