package com.piggymetrics.auth.config.password;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Identifies the browser client on a password-grant token request.
 *
 * <p>The browser client has no secret, as it had before the upgrade. The authorization server
 * only authenticates a client without one for the authorization code grant with a proof key, so
 * the password grant this application carries over needs its own converter: it reads the client
 * id off the request and leaves the provider to decide whether that client may be used this way.
 */
public class PublicClientPasswordAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (!OAuth2PasswordAuthenticationToken.PASSWORD.getValue().equals(grantType)) {
			return null;
		}
		String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId)) {
			return null;
		}
		// A client that presents a secret, here or in the Authorization header, is authenticated
		// by the server's own converters instead.
		if (StringUtils.hasText(request.getParameter(OAuth2ParameterNames.CLIENT_SECRET))
				|| StringUtils.hasText(request.getHeader("Authorization"))) {
			return null;
		}

		Map<String, Object> parameters = new HashMap<>();
		request.getParameterMap().forEach((key, values) -> {
			if (!key.equals(OAuth2ParameterNames.CLIENT_ID) && values.length > 0) {
				parameters.put(key, values.length == 1 ? values[0] : values.clone());
			}
		});
		return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null,
				parameters);
	}
}
