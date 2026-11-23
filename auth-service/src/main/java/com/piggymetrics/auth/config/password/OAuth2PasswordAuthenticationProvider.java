package com.piggymetrics.auth.config.password;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

/**
 * Issues tokens for the resource owner password credentials grant: the endpoint authenticates
 * the client, and the application's own {@link AuthenticationManager} authenticates the
 * resource owner against the Mongo user store.
 */
public class OAuth2PasswordAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private final OAuth2AuthorizationService authorizationService;

	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	private final AuthenticationManager authenticationManager;

	public OAuth2PasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
			AuthenticationManager authenticationManager) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2PasswordAuthenticationToken passwordAuthentication = (OAuth2PasswordAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = authenticatedClient(passwordAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (registeredClient == null || !registeredClient.getAuthorizationGrantTypes()
				.contains(OAuth2PasswordAuthenticationToken.PASSWORD)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}

		Set<String> authorizedScopes = authorizedScopes(registeredClient, passwordAuthentication.getScopes());

		Authentication resourceOwner;
		try {
			resourceOwner = this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					passwordAuthentication.getUsername(), passwordAuthentication.getPassword()));
		}
		catch (AuthenticationException ex) {
			throw new OAuth2AuthenticationException(
					new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Bad resource owner credentials", ERROR_URI), ex);
		}

		DefaultOAuth2TokenContext.Builder contextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(resourceOwner)
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorizedScopes(authorizedScopes)
				.authorizationGrantType(OAuth2PasswordAuthenticationToken.PASSWORD)
				.authorizationGrant(passwordAuthentication);

		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(resourceOwner.getName())
				.authorizationGrantType(OAuth2PasswordAuthenticationToken.PASSWORD)
				.authorizedScopes(authorizedScopes)
				.attribute(Principal.class.getName(), resourceOwner);

		OAuth2TokenContext accessTokenContext = contextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(accessTokenContext);
		if (generatedAccessToken == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", ERROR_URI));
		}
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
				generatedAccessToken.getExpiresAt(), authorizedScopes);
		if (generatedAccessToken instanceof ClaimAccessor claims) {
			authorizationBuilder.token(accessToken, metadata -> metadata
					.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims.getClaims()));
		}
		else {
			authorizationBuilder.accessToken(accessToken);
		}

		OAuth2RefreshToken refreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			OAuth2TokenContext refreshTokenContext = contextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
			OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(refreshTokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
						"The token generator failed to generate the refresh token.", ERROR_URI));
			}
			refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(refreshToken);
		}

		this.authorizationService.save(authorizationBuilder.build());

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken,
				passwordAuthentication.getAdditionalParameters());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * The scopes the token may carry: what the client asked for, which must be a subset of what
	 * it is registered for; everything it is registered for when it asked for nothing.
	 */
	private static Set<String> authorizedScopes(RegisteredClient registeredClient, Set<String> requestedScopes) {
		if (requestedScopes.isEmpty()) {
			return new LinkedHashSet<>(registeredClient.getScopes());
		}
		for (String requestedScope : requestedScopes) {
			if (!registeredClient.getScopes().contains(requestedScope)) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
			}
		}
		return new LinkedHashSet<>(requestedScopes);
	}

	private static OAuth2ClientAuthenticationToken authenticatedClient(Authentication authentication) {
		if (authentication.getPrincipal() instanceof OAuth2ClientAuthenticationToken clientPrincipal
				&& clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}
}
