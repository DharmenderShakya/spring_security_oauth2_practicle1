package com.Spring_Security_oauth2_practicle1.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final OurUserDetailsService ourUserDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final LoggingFilter loggingFilter;


    public SecurityConfig(OurUserDetailsService ourUserDetailsService,
                          JwtAuthenticationFilter jwtAuthenticationFilter,
                          LoggingFilter loggingFilter) {
        this.ourUserDetailsService = ourUserDetailsService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.loggingFilter = loggingFilter;
      
    }

    @Autowired
    private CustomAuthEntryPoint euAuthEntryPoint;

    @Autowired
    private CustomAccessDeniedHandler cuDeniedHandler;
    
    @Autowired
    private SocialAppService socialAppService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable())

            //  Authorization Rules
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/", "/login", "/error", "/webjars/**").permitAll()
                    .requestMatchers("/auth/**").permitAll()
                    .requestMatchers("/h2-console/**").permitAll()
                    .requestMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated()
            )

            //  Exception Handling (Your Custom)
            .exceptionHandling(ex -> ex
                    .authenticationEntryPoint(euAuthEntryPoint)
                    .accessDeniedHandler(cuDeniedHandler)
            )

            // OAuth2 Login
            .oauth2Login(oauth -> oauth
                    .loginPage("/") // custom login page (optional)
                    .userInfoEndpoint(userInfo -> userInfo
                            .userService(socialAppService) //  your service
                    )
                    .defaultSuccessUrl("/user", true)
            )

            //  Logout
            .logout(logout -> logout
                    .logoutUrl("/logout")
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
            )

            //  JWT Filter (only needed if you use JWT for APIs)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

            // Logging Filter
            .addFilterBefore(loggingFilter, JwtAuthenticationFilter.class)

            //  Disable default login & basic auth
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable());

        //  Needed for H2 Console (if used)
        http.headers(headers -> headers.frameOptions(frame -> frame.disable()));

        return http.build();
    }

    // Password Encoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Authentication Provider (for JWT / normal login)
    @Bean
    public AuthenticationProvider authenticationProvider() {

        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(ourUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    // Authentication Manager
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
