package com.springcloud.session.oauth2.filter;

import com.google.common.collect.Maps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A composite token enhancer that loops over its delegate enhancers.
 * 
 * @author xienjiang
 * @createdAt 2016.3.25
 */
@Component
public class TokenEnhancerChainFilter implements TokenEnhancer {

	Logger logger = LoggerFactory.getLogger(TokenEnhancerChainFilter.class);

	private List<TokenEnhancer> delegates = Collections.emptyList();

	/**
	 * @param delegates the delegates to set
	 */
	public void setTokenEnhancers(List<TokenEnhancer> delegates) {
		this.delegates = delegates;
	}

	/**
	 * Loop over the {@link #setTokenEnhancers(List) delegates} passing the result into the next member of the chain.
	 *
	 * @see org.springframework.security.oauth2.provider.token.TokenEnhancer#enhance(org.springframework.security.oauth2.common.OAuth2AccessToken,
	 * org.springframework.security.oauth2.provider.OAuth2Authentication)
	 */
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		DefaultOAuth2AccessToken tempResult = (DefaultOAuth2AccessToken) accessToken;


		final Map<String, Object> additionalInformation = new HashMap<String, Object>();

		Map<String, String> details = Maps.newHashMap();
		Object userDetails = authentication.getUserAuthentication().getDetails();
		if (userDetails != null) {
			details = (Map<String, String>) userDetails;
		}


		//you can do extra functions from authentication details

		OAuth2AccessToken result = tempResult;
		for (TokenEnhancer enhancer : delegates) {
			result = enhancer.enhance(result, authentication);
		}
		return result;
	}

}