package com.piggymetrics.auth.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import com.piggymetrics.auth.config.password.OAuth2PasswordAuthenticationConverter;
import com.piggymetrics.auth.config.password.OAuth2PasswordAuthenticationProvider;
import com.piggymetrics.auth.config.password.OAuth2PasswordAuthenticationToken;
import com.piggymetrics.auth.config.password.PublicClientPasswordAuthenticationConverter;
import com.piggymetrics.auth.config.password.PublicClientPasswordAuthenticationProvider;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The authorization server: the clients PiggyMetrics issues tokens to, and the grants they may
 * use. The browser client exchanges a user's name and password for a token; each back-end
 * service exchanges its own secret for a token with the "server" scope.
 *
 * @author cdov
 */
@Configuration
public class OAuth2AuthorizationConfig {


	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurity(HttpSecurity http,
			OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<?> tokenGenerator,
			AuthenticationManager authenticationManager, RegisteredClientRepository registeredClients)
			throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
				.clientAuthentication(clientAuthentication -> clientAuthentication
						.authenticationConverter(new PublicClientPasswordAuthenticationConverter())
						.authenticationProvider(
								new PublicClientPasswordAuthenticationProvider(registeredClients)))
				.tokenEndpoint(tokenEndpoint -> tokenEndpoint
						.accessTokenRequestConverter(new OAuth2PasswordAuthenticationConverter())
						.authenticationProvider(new OAuth2PasswordAuthenticationProvider(authorizationService,
								tokenGenerator, authenticationManager)));

		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

		return http.build();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository(Environment env, PasswordEncoder encoder) {
		RegisteredClient browser = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("browser")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(OAuth2PasswordAuthenticationToken.PASSWORD)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.scope("ui")
				.clientSettings(ClientSettings.builder().requireProofKey(false).build())
				.build();

		return new InMemoryRegisteredClientRepository(browser,
				serviceClient("account-service", env.getProperty("ACCOUNT_SERVICE_PASSWORD"), encoder),
				serviceClient("statistics-service", env.getProperty("STATISTICS_SERVICE_PASSWORD"), encoder),
				serviceClient("notification-service", env.getProperty("NOTIFICATION_SERVICE_PASSWORD"), encoder));
	}

	/**
	 * A back-end service: it presents its own secret and gets a token scoped "server", which is
	 * the scope the services' own endpoints require of each other. The secret is stored hashed,
	 * so the deployment may give several services the same one.
	 */
	private static RegisteredClient serviceClient(String clientId, String secret, PasswordEncoder encoder) {
		return RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(clientId)
				.clientSecret(encoder.encode(secret == null ? "" : secret))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.scope("server")
				.tokenSettings(TokenSettings.builder().build())
				.build();
	}

	@Bean
	public OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	/**
	 * The issuer is left to the server, which takes it from the request it answers. The services
	 * reach this one by a single name and port, so that is the issuer their tokens carry and the
	 * one their resource-server configuration expects.
	 */
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	/**
	 * The signing key. It is generated at start-up and held in memory, which is what the
	 * in-memory token store it replaces did: a restart invalidates the tokens it issued.
	 */
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString())
				.build();
		return new ImmutableJWKSet<>(new JWKSet(rsaKey));
	}

	@Bean
	public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
		JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
		jwtGenerator.setJwtCustomizer(userNameCustomizer());
		return new DelegatingOAuth2TokenGenerator(jwtGenerator, new OAuth2RefreshTokenGenerator());
	}

	/**
	 * The services read the caller's name off the token, so the user name travels in a claim of
	 * its own as well as in the subject.
	 */
	private static OAuth2TokenCustomizer<JwtEncodingContext> userNameCustomizer() {
		return context -> {
			if (OAuth2PasswordAuthenticationToken.PASSWORD.equals(context.getAuthorizationGrantType())) {
				context.getClaims().claim("user_name", context.getPrincipal().getName());
			}
		};
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	private static KeyPair generateRsaKey() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException("the authorization server could not create its signing key", ex);
		}
	}
}
