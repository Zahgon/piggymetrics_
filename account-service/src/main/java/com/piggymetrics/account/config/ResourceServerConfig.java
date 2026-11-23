package com.piggymetrics.account.config;

import feign.RequestInterceptor;
import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The service as a resource server: it accepts the access tokens the authorization server
 * issues, and it presents its own client credentials when it calls the other services.
 *
 * @author cdov
 */
@Configuration
@EnableWebSecurity
public class ResourceServerConfig {

	private static final String CLIENT_REGISTRATION_ID = "account-service";

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				.authorizeHttpRequests(requests -> requests
						// Spring Security 6 authorizes the error dispatch as well as the request, so an
						// error raised inside an endpoint would be answered with 401 instead of the
						// status it means. The container renders the error of a request that has
						// already been authorized, so letting it through restores what callers saw.
						.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
						.requestMatchers("/", "/demo").permitAll()
						.anyRequest().authenticated())
				.csrf(csrf -> csrf.disable())
				.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
		return http.build();
	}

	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clients,
			OAuth2AuthorizedClientService authorizedClients) {
		AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(clients, authorizedClients);
		manager.setAuthorizedClientProvider(
				OAuth2AuthorizedClientProviderBuilder.builder().clientCredentials().build());
		return manager;
	}

	/**
	 * Puts this service's own access token on every outgoing Feign call, which is what the
	 * other services' resource-server rules require of it.
	 */
	@Bean
	public RequestInterceptor oauth2FeignRequestInterceptor(OAuth2AuthorizedClientManager clientManager) {
		return template -> {
			OAuth2AuthorizedClient client = clientManager.authorize(OAuth2AuthorizeRequest
					.withClientRegistrationId(CLIENT_REGISTRATION_ID)
					.principal(CLIENT_REGISTRATION_ID)
					.build());
			if (client != null) {
				template.header("Authorization", "Bearer " + client.getAccessToken().getTokenValue());
			}
		};
	}
}
