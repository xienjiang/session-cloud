package com.springcloud.session.oauth2.exception;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

import java.io.IOException;
import java.util.Map;

/**
 * spring oauth2.0 中自定义异常输出文案
 * @author JohnnyJiang
 * @since 2017.02.16
 */
@Slf4j
public class CustomOauthMessageConverter extends MappingJackson2HttpMessageConverter {


	//for example you can chagne error msg render
    private static Map<String,String> errorMap = Maps.newHashMap();
	static {
		errorMap.put(OAuth2Exception.URI, OAuth2Exception.URI);
		errorMap.put(OAuth2Exception.INVALID_REQUEST, OAuth2Exception.INVALID_REQUEST);
		errorMap.put(OAuth2Exception.INVALID_CLIENT, OAuth2Exception.INVALID_CLIENT);
		errorMap.put(OAuth2Exception.INVALID_GRANT, OAuth2Exception.INVALID_GRANT);
		errorMap.put(OAuth2Exception.UNAUTHORIZED_CLIENT, OAuth2Exception.UNAUTHORIZED_CLIENT);
		errorMap.put(OAuth2Exception.UNSUPPORTED_GRANT_TYPE, OAuth2Exception.UNSUPPORTED_GRANT_TYPE);
		errorMap.put(OAuth2Exception.INVALID_SCOPE, OAuth2Exception.INVALID_SCOPE);
		errorMap.put(OAuth2Exception.INVALID_TOKEN, OAuth2Exception.INVALID_TOKEN);
		errorMap.put(OAuth2Exception.REDIRECT_URI_MISMATCH, OAuth2Exception.REDIRECT_URI_MISMATCH);
		errorMap.put(OAuth2Exception.UNSUPPORTED_RESPONSE_TYPE, OAuth2Exception.UNSUPPORTED_RESPONSE_TYPE);
		errorMap.put(OAuth2Exception.ACCESS_DENIED, OAuth2Exception.ACCESS_DENIED);
	}

	@Override
	protected void writeInternal(Object object, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
	    super.writeInternal(transformObject(object), outputMessage);
	}
	
	protected Object transformObject(Object object) {
	    if(object instanceof OAuth2Exception) {
	    	OAuth2Exception authException = (OAuth2Exception) object;
	    	
	    	log.info("oauth2 exception:" + authException.getHttpErrorCode());
	    	return ImmutableMap.of(errorMap.get(authException.getOAuth2ErrorCode()),
					authException.getMessage());
	    }

	    return object;
	}
}