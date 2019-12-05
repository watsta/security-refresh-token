package hu.krisz.securityrefreshtoken.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import hu.krisz.securityrefreshtoken.security.*;
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
    private static final String REFRESH_URL = "/refresh";

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
        auth.authenticationProvider(refreshTokenAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(configurer ->
                configurer
                        .antMatchers(HttpMethod.POST, LOGIN_URL, REFRESH_URL).permitAll()
                        .anyRequest().authenticated()
        ).csrf(configurer ->
                configurer.disable()
        ).sessionManagement(configurer ->
                configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        ).addFilter(usernamePasswordAuthenticationFilter())
        .addFilterBefore(refreshTokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
        .addFilterAfter(jwtAuthorizationFilter(), RefreshTokenAuthenticationFilter.class);
    }

    private UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter() throws Exception {
        var requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.POST.toString());
        var filter = new UsernamePasswordAuthenticationFilter();
        filter.setRequiresAuthenticationRequestMatcher(requestMatcher);
        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationSuccessHandler(credentialsAuthenticationSuccessHandlerBean());
        return filter;
    }

    private RefreshTokenAuthenticationFilter refreshTokenAuthenticationFilter() throws Exception {
        var filter = new RefreshTokenAuthenticationFilter(new AntPathRequestMatcher(REFRESH_URL, "POST"));
        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationSuccessHandler(tokenRefreshSuccessHandlerBean());
        return filter;
    }

    private JwtAuthorizationFilter jwtAuthorizationFilter() {
        return new JwtAuthorizationFilter(accessTokenServiceBean());
    }


    private RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider() {
        return new RefreshTokenAuthenticationProvider(refreshTokenServiceBean());
    }

    private DaoAuthenticationProvider daoAuthenticationProvider() {
        var authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        return authenticationProvider;
    }

    @Bean
    public CredentialsAuthenticationSuccessHandler credentialsAuthenticationSuccessHandlerBean() {
        return new CredentialsAuthenticationSuccessHandler(accessTokenServiceBean(), refreshTokenServiceBean(), objectMapper);
    }

    @Bean
    public AccessTokenService accessTokenServiceBean() {
        return new AccessTokenService(Keys.secretKeyFor(SignatureAlgorithm.HS512), 300);
    }

    @Bean
    public RefreshTokenService refreshTokenServiceBean() {
        return new RefreshTokenService(refreshTokenStoreBean(), 864_000);
    }

    @Bean
    public TokenRefreshSuccessHandler tokenRefreshSuccessHandlerBean() {
        return new TokenRefreshSuccessHandler(accessTokenServiceBean(), refreshTokenServiceBean(), userDetailsService(), objectMapper);
    }

    @Bean
    public RefreshTokenStore refreshTokenStoreBean() {
        return new InMemoryRefreshTokenStore();
    }
}
