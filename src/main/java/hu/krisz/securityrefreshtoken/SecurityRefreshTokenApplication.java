package hu.krisz.securityrefreshtoken;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.Random;

@SpringBootApplication(scanBasePackages = "hu.krisz.securityrefreshtoken")
public class SecurityRefreshTokenApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityRefreshTokenApplication.class, args);
    }

    @Bean
    public RandomNumberController randomNumberControllerBean(Random randomNumberGeneratorBean) {
        return new RandomNumberController(randomNumberGeneratorBean);
    }

    @Bean
    public Random randomNumberGeneratorBean() {
        return new Random();
    }

}
