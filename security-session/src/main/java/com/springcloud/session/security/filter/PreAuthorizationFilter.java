package com.springcloud.session.security.filter;

import com.springcloud.session.oauth2.domain.CustomUserDetails;
import com.springcloud.session.oauth2.domain.User;
import com.springcloud.session.oauth2.provider.CustomAuthenticationProvider;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;

@Component
public class PreAuthorizationFilter extends GenericFilterBean {
    static Logger logger = LoggerFactory.getLogger(PreAuthorizationFilter.class);
	
	 private static final String COOKIE__HASH__SITE = "__hash__";
	 private static final String COOKIE__VERIFY__ = "__verify__";
	 private static final String ENCRYPT_SALT = "&$9Q34(!~*-+|/*$%@";
	
	@Autowired
    private AuthenticationManager authenticationManager;
	
    private RememberMeServices rememberMeServices = new NullRememberMeServices();


	/**
	 * add custom filter logic ,for example below
	 * @param req
	 * @param res
	 * @param chain
	 * @throws IOException
	 * @throws ServletException
	 */
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

		String __verify__ = getCookieValueByName(request,COOKIE__VERIFY__);
		logger.info("__verify__:{}" + __verify__);


        	try {
				if(StringUtils.isNotBlank(__verify__)){
								Authentication authResult = CustomAuthenticationProvider.createUserNamePasswordAuthWithBid(
										"custom",
										StringUtils.EMPTY,
										new CustomUserDetails(new User(__verify__,__verify__)));
								
								SecurityContextHolder.getContext().setAuthentication(authResult);

				                rememberMeServices.loginSuccess(request, response, authResult);

				                onSuccessfulAuthentication(request, response, authResult);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

        
        chain.doFilter(request, response);
    }


	public Authentication attemptAuthentication(String userName, String password) throws AuthenticationException {
        if (userName == null) {
        	userName = "";
        }

        if (password == null) {
            password = "";
        }
        
        userName = userName.trim();

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(userName, password);

        return authenticationManager.authenticate(authRequest);
    }	
	
	
	public static String getCookieValueByName(HttpServletRequest request,String name){
        Cookie[] cookies = request.getCookies();
        if(null != cookies){
            for(Cookie cookie : cookies){
            	if(StringUtils.equals(name, cookie.getName())){
            		return cookie.getValue();
            	}
            }
        } 
        
        return StringUtils.EMPTY;
    }
	
	protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            Authentication authResult) throws IOException {
    }
	
}