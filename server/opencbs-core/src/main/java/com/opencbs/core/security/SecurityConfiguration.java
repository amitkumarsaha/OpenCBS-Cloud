package com.opencbs.core.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@SuppressWarnings("unused")
public class SecurityConfiguration{

//    private static final RequestMatcher PUBLIC_URLS = new OrRequestMatcher(new AntPathRequestMatcher("/public/**/**"));
//    private static final RequestMatcher PROTECTED_URLS = new NegatedRequestMatcher(PUBLIC_URLS);
//    private final AuthenticationEntryPoint AuthenticationEntryPoint;
//
//    @Bean
//    private static AuthenticationEntryPoint forbiddenEntryPoint() {
//        return new HttpStatusEntryPoint(FORBIDDEN);
//    }

//    private final YamlConfig yamlConfig;
//    private final Logger LOGGER = LoggerFactory.getLogger(SecurityConfig.class);

//    public SecurityConfig(YamlConfig yamlConfig) {
//        this.yamlConfig = yamlConfig;
//    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sessionManager  -> sessionManager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint(
                    (request, response, exception) -> {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, exception.getMessage());
                    }))
            .authorizeHttpRequests(authorizeHttpRequest -> authorizeHttpRequest
                .requestMatchers(
                    "/actuator/health",
                    "/actuator/metrics",
                    "/actuator/metrics/**",
                    "/v2/api-docs/**",
                    "/v3/api-docs/**",
                    "/swagger-ui/**",
                    "/swagger-ui.html",
                    "/swagger-resources/**",
                    "/api/monitor/**",
                    "/api/authentication/**",
                    "/*",
                    "/assets/**",
                    "index.html",
                    "/docs/**",
                    "/webjars/**"
                )
                .permitAll()
                .anyRequest()
                .authenticated()
            )
            .authorizeHttpRequests(authorizeHttpRequest -> authorizeHttpRequest
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/api").permitAll()
                .requestMatchers("/api/login", "/api/login/update-password", "/api/login/password-reset").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/profiles/people/{personId}/attachments/{attachmentId}").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/profiles/companies/{companiesId}/attachments/{attachmentId}").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/profiles/groups/{groupId}/attachments/{attachmentId}").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/loan-applications/{loanApplicationId}/attachments/{attachmentId}").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/loans/{loanId}/attachments/{attachmentId}").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/info").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/system-settings").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/utils/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/utils/**").permitAll()
                .anyRequest().authenticated()
        );

//        http.addFilterBefore(new SecurityFilter(), UsernamePasswordAuthenticationFilter.class); // custom protocol Authorization
        return http.build();

    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new
                UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
//        config.setAllowedOriginPatterns(yamlConfig.getCorsAllowedList());
//        LOGGER.info("Added CORS allowed patterns: '{}' ", String.join("', '", yamlConfig.getCorsAllowedList()));
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
