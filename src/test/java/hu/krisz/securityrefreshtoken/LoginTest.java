package hu.krisz.securityrefreshtoken;

import com.fasterxml.jackson.databind.ObjectMapper;
import hu.krisz.securityrefreshtoken.security.token.TokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class LoginTest {
    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders
                .webAppContextSetup(webApplicationContext)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    public void testLogin() throws Exception {
        TokenResponse tokenResponse = login();

        assertThat(tokenResponse.getAccessToken(), is(notNullValue()));
        assertTrue(tokenResponse.getExpiresIn() > 0);
    }

    @Test
    public void testLoginWithInvalidCredentials() throws Exception {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("username", "user");
        params.add("password", "invalidPassword");

        mvc.perform(MockMvcRequestBuilders
                .post("/login")
                .params(params))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    public void testGetRandomAfterLogin() throws Exception {
        TokenResponse tokenResponse = login();

        HttpHeaders httpHeaders = createAuthorizationHeader(tokenResponse.getAccessToken());
        var result = mvc.perform(MockMvcRequestBuilders
                .get("/random")
                .headers(httpHeaders))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        var randomNumberResponse = objectMapper.readValue(result, RandomNumberResponse.class);

        assertThat(randomNumberResponse.getRandomNumber(), instanceOf(Integer.class));
    }

    private TokenResponse login() throws Exception {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("username", "user");
        params.add("password", "password");

        var result = mvc.perform(MockMvcRequestBuilders
                .post("/login")
                .params(params))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return objectMapper.readValue(result, TokenResponse.class);
    }

    private HttpHeaders createAuthorizationHeader(String accessToken) {
        MultiValueMap<String, String> headerParams = new LinkedMultiValueMap<>();
        headerParams.add(HttpHeaders.AUTHORIZATION, accessToken);
        return new HttpHeaders(headerParams);
    }
}
