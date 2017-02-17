package com.springcloud.session.oauth2.provider;

import com.google.common.collect.Maps;
import com.springcloud.session.oauth2.domain.CustomUserDetails;
import com.springcloud.session.oauth2.domain.User;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * 自定义认证处理逻辑
 * @author JohnnyJiang
 * @since 2017.02.17
 */
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    public Authentication authenticate(Authentication auth) throws AuthenticationException {
		String username = (String) auth.getPrincipal();
		String password = (String) auth.getCredentials();
		
		try {

			//here youcan identity account
			UserDetails user =  new CustomUserDetails(new User(username,password));
			return createUserNamePasswordAuthWithBid(
					username, password, user);
			
		} catch (Exception e) {
			throw new BadCredentialsException("Username/Password does not match for " + auth.getPrincipal());
		}		
	}

	public static UsernamePasswordAuthenticationToken createUserNamePasswordAuthWithBid(
			String username, String password, UserDetails user) {
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, user.getAuthorities());
		Map<String, String> extraDetails = Maps.newHashMap();
		authToken.setDetails(extraDetails);
		return authToken;
	}

	public boolean supports(Class authentication) {
		return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
	}

}