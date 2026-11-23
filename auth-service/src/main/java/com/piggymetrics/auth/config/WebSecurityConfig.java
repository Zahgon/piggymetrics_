package com.piggymetrics.auth.config;

import com.piggymetrics.auth.service.security.MongoUserDetailsService;
import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Application security: the user store the authorization server authenticates against, and the
 * filter chain that guards everything the authorization server itself does not claim.
 *
 * @author cdov
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	/**
	 * Guards the service's own endpoints. The authorization server's protocol endpoints are
	 * claimed by a higher-precedence chain, so this one only ever sees application requests;
	 * they are resource-server requests carrying an access token this service issued.
	 */
	@Bean
	@Order(2)
	public SecurityFilterChain applicationSecurity(HttpSecurity http) throws Exception {
		http
				.authorizeHttpRequests(requests -> requests
						// Spring Security 6 authorizes the error dispatch as well as the request; left
						// closed, every error an endpoint raises would be answered with 401.
						.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
						.anyRequest().authenticated())
				.csrf(csrf -> csrf.disable())
				.oauth2ResourceServer(server -> server.jwt(jwt -> {}));
		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
	 * Authenticates the resource owner for the password grant: the Mongo-backed user store,
	 * with the BCrypt hashes the user service writes.
	 */
	@Bean
	public AuthenticationManager authenticationManager(MongoUserDetailsService userDetailsService,
			PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
		provider.setPasswordEncoder(passwordEncoder);
		return new ProviderManager(provider);
	}
}
