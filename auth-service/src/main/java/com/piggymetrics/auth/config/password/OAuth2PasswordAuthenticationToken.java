package com.piggymetrics.auth.config.password;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

/**
 * The token request of the resource owner password credentials grant.
 *
 * <p>OAuth 2.1 dropped this grant and Spring Authorization Server therefore does not ship it.
 * PiggyMetrics' browser client exchanges a username and a password for an access token, so the
 * grant is carried over as a custom authorization grant through the server's extension points.
 */
public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");

	private final String username;

	private final String password;

	private final Set<String> scopes;

	public OAuth2PasswordAuthenticationToken(Authentication clientPrincipal, String username, String password,
			Set<String> scopes, Map<String, Object> additionalParameters) {
		super(PASSWORD, clientPrincipal, additionalParameters);
		Assert.hasText(username, "username cannot be empty");
		Assert.notNull(password, "password cannot be null");
		this.username = username;
		this.password = password;
		this.scopes = Collections.unmodifiableSet(scopes == null ? Collections.emptySet() : scopes);
	}

	public String getUsername() {
		return this.username;
	}

	public String getPassword() {
		return this.password;
	}

	public Set<String> getScopes() {
		return this.scopes;
	}
}
