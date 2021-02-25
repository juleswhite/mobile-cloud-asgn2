package org.magnum.mobilecloud.video.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@Order(1)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    /**
     *
     *  WARNING!!!!!
     *
     * Do not use this code in production.
     *
     *
     * Please understand Spring Security in detail and
     * configure the application appropriately!
     *
     * https://spring.io/guides/topicals/spring-security-architecture
     */
    @Value("${users.user1.name}")
    private String user1;

    @Value("${users.user2.name}")
    private String user2;

    @Value("${users.user1.password}")
    private String user1Password;

    @Value("${users.user2.password}")
    private String user2Password;

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers()
                .antMatchers("/login", "/oauth/authorize")
                .and()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser(user1)
                .password(passwordEncoder().encode(user1Password))
                .roles("USER","ADMIN")
                .and()
                .withUser(user2)
                .password(user2Password)
                .roles("USER");

    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}