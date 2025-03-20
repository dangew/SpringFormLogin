package com.example.login_test;

import com.example.login_test.filter.CookieRemovalFilter;
import jakarta.servlet.ServletException;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.io.IOException;

@Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final CookieRemovalFilter cookieRemovalFilter;
    private final CustomLogoutHandler customLogoutHandler;

    @Bean
    public static BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)// Prevents session creation
                .maximumSessions(1).maxSessionsPreventsLogin(false));
        http.httpBasic(AbstractHttpConfigurer::disable);
        http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(
                authorizeRequests -> authorizeRequests
                    .requestMatchers("/admin/**").hasRole("ADMIN")
                    .requestMatchers("/user/**").authenticated()
                    .anyRequest().permitAll())
            // formlogin setting
            .formLogin(
                formLogin -> formLogin
                    .loginPage("/login")
                    .loginProcessingUrl("/loginProc")
                    .failureUrl("/login?error=true")
                    .usernameParameter("email")
                    .defaultSuccessUrl("/api/user/loginOk"))
            // logout setting
            .logout(
                logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/user/userInfo")
                    .clearAuthentication(true) // Clears authentication without invalidating the session
                    .invalidateHttpSession(true) // Prevents session invalidation (no new session)
                    .deleteCookies("JSESSIONID")); // Deletes existing JSESSIONID without creating a new one

        // add filter for cors (we will connect with react)
        http.addFilterBefore(corsFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterAfter(cookieRemovalFilter, LogoutFilter.class); // 로그아웃 필터 이후에 실행
        http.cors(Customizer.withDefaults());

        return http.build();
    }
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("http://localhost:3000");// 리액트 서버
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(source);
    }

}
