package hu.krisz.securityrefreshtoken.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import hu.krisz.securityrefreshtoken.security.CredentialsAuthenticationSuccessHandler;
import hu.krisz.securityrefreshtoken.security.JwtAuthorizationFilter;
import hu.krisz.securityrefreshtoken.security.token.access.AccessTokenService;
import hu.krisz.securityrefreshtoken.security.token.refresh.InMemoryRefreshTokenStore;
import hu.krisz.securityrefreshtoken.security.token.refresh.RefreshTokenService;
import hu.krisz.securityrefreshtoken.security.token.refresh.RefreshTokenStore;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private static final String LOGIN_URL = "/login";

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("user")
                .password("{noop}password")
                .roles("admin");

        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(configurer ->
                configurer
                        .antMatchers(HttpMethod.POST, LOGIN_URL).permitAll()
                        .anyRequest().authenticated()
        ).csrf(configurer ->
                configurer.disable()
        ).sessionManagement(configurer ->
                configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        ).addFilter(usernamePasswordAuthenticationFilter())
        .addFilterAfter(jwtAuthorizationFilterBean(), UsernamePasswordAuthenticationFilter.class);
    }

    private UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter() throws Exception {
        var requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.POST.toString());
        var filter = new UsernamePasswordAuthenticationFilter();
        filter.setRequiresAuthenticationRequestMatcher(requestMatcher);
        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationSuccessHandler(credentialsAuthenticationSuccessHandlerBean());
        return filter;
    }

    @Bean
    public CredentialsAuthenticationSuccessHandler credentialsAuthenticationSuccessHandlerBean() {
        return new CredentialsAuthenticationSuccessHandler(accessTokenServiceBean(), refreshTokenService(), objectMapper);
    }

    @Bean
    public AccessTokenService accessTokenServiceBean() {
        return new AccessTokenService(Keys.secretKeyFor(SignatureAlgorithm.HS512), 300);
    }

    private RefreshTokenService refreshTokenService() {
        return new RefreshTokenService(refreshTokenStore(), 864_000);
    }

    private DaoAuthenticationProvider daoAuthenticationProvider() {
        var authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        return authenticationProvider;
    }

    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilterBean() {
        return new JwtAuthorizationFilter(accessTokenServiceBean());
    }

    private RefreshTokenStore refreshTokenStore() {
        return new InMemoryRefreshTokenStore();
    }
}
