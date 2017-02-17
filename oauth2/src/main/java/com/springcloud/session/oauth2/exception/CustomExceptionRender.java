package com.springcloud.session.oauth2.exception;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.http.converter.jaxb.JaxbOAuth2ExceptionMessageConverter;
import org.springframework.security.oauth2.provider.error.DefaultOAuth2ExceptionRenderer;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 自定义Spring Oauth2.0 异常输出渲染
 * @author JohnnyJiang
 * @since 2017.02.16
 */
@Component
public class CustomExceptionRender extends DefaultOAuth2ExceptionRenderer {

	public CustomExceptionRender() {
		setMessageConverters(getMessageConverters());
	}

	private List<HttpMessageConverter<?>> getMessageConverters() {
		List<HttpMessageConverter<?>> result = new ArrayList<HttpMessageConverter<?>>();
		result.add(new CustomOauthMessageConverter());
		result.add(new JaxbOAuth2ExceptionMessageConverter());
		return result;
	}
}
