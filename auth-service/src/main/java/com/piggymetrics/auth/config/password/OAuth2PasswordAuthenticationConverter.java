package com.piggymetrics.auth.config.password;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Reads a password-grant token request off the token endpoint.
 */
public class OAuth2PasswordAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (!OAuth2PasswordAuthenticationToken.PASSWORD.getValue().equals(grantType)) {
			return null;
		}

		MultiValueMap<String, String> parameters = parameters(request);

		String username = single(parameters, OAuth2ParameterNames.USERNAME);
		String password = single(parameters, OAuth2ParameterNames.PASSWORD);

		// The scope is optional: a request that asks for none gets the scopes the client is
		// registered for, which is what the grant did before the upgrade. Sending it more than
		// once is still an invalid request.
		Set<String> requestedScopes = Collections.emptySet();
		String scope = optional(parameters, OAuth2ParameterNames.SCOPE);
		if (StringUtils.hasText(scope)) {
			requestedScopes = new HashSet<>(
					Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, values) -> {
			if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) && !key.equals(OAuth2ParameterNames.SCOPE)
					&& !key.equals(OAuth2ParameterNames.USERNAME) && !key.equals(OAuth2ParameterNames.PASSWORD)) {
				additionalParameters.put(key, values.size() == 1 ? values.get(0) : values.toArray(new String[0]));
			}
		});

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
		return new OAuth2PasswordAuthenticationToken(clientPrincipal, username, password, requestedScopes,
				additionalParameters);
	}

	/**
	 * The request's parameters, read the way the server's own converters read them.
	 */
	private static MultiValueMap<String, String> parameters(HttpServletRequest request) {
		Map<String, String[]> parameterMap = request.getParameterMap();
		MultiValueMap<String, String> parameters = new org.springframework.util.LinkedMultiValueMap<>(
				parameterMap.size());
		parameterMap.forEach((key, values) -> {
			for (String value : values) {
				parameters.add(key, value);
			}
		});
		return parameters;
	}

	/**
	 * A required token request parameter. It may be sent only once; anything else is an invalid
	 * request.
	 */
	private static String single(MultiValueMap<String, String> parameters, String name) {
		List<String> values = parameters.get(name);
		if (values == null || values.size() != 1 || !StringUtils.hasText(values.get(0))) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}
		return values.get(0);
	}

	/**
	 * An optional token request parameter: absent is allowed, repeated is not.
	 */
	private static String optional(MultiValueMap<String, String> parameters, String name) {
		List<String> values = parameters.get(name);
		if (values == null) {
			return null;
		}
		if (values.size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}
		return values.get(0);
	}
}
