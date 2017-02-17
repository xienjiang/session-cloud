package com.springcloud.session.oauth2.provider;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Slf4j
public class CustomAuthenticationSuccessHandler implements
		AuthenticationSuccessHandler {

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request,
										HttpServletResponse response, Authentication auth)
			throws IOException, ServletException {

		String ru = (String) request.getSession().getAttribute("ru");
		request.getSession().removeAttribute("ru");
		if (StringUtils.isNotEmpty(ru)) {
			response.sendRedirect(ru);
		} else {
			response.sendRedirect("/login.jsp");
		}


	}

}
