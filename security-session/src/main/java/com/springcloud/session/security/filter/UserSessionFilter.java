package com.springcloud.session.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import com.springcloud.session.security.domain.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.HttpSessionManager;

/**
 * 拦截所有的HTTP REQUEST
 * @since 2017.02.14
 */
@Slf4j
public class UserSessionFilter implements Filter {

	public void init(FilterConfig filterConfig) throws ServletException {}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;

		HttpSessionManager sessionManager = (HttpSessionManager) httpRequest.getAttribute(HttpSessionManager.class.getName());
		SessionRepository<Session> repo = (SessionRepository<Session>) httpRequest.getAttribute(SessionRepository.class.getName());

		String currentSessionAlias = sessionManager.getCurrentSessionAlias(httpRequest);
		Map<String, String> sessionIds = sessionManager.getSessionIds(httpRequest);
		String unauthenticatedAlias = null;

		String contextPath = httpRequest.getContextPath();
		List<User> users = new ArrayList<User>();
		User user = null;
		for (Map.Entry<String, String> entry : sessionIds.entrySet()) {
			String alias = entry.getKey();
			String sessionId = entry.getValue();

			Session session = repo.getSession(sessionId);
			if (session == null) {
				continue;
			}

			String username = session.getAttribute("username");
			if (username == null) {
				unauthenticatedAlias = alias;
				continue;
			}

			String logoutUrl = sessionManager.encodeURL("./logout", alias);
			String switchAccountUrl = sessionManager.encodeURL("./", alias);
			User newUser = new User(username, logoutUrl, switchAccountUrl);
			if (currentSessionAlias.equals(alias)) {
				user = newUser;
			}
			else {
				users.add(newUser);
			}
		}

		String addAlias = unauthenticatedAlias == null ?
				sessionManager.getNewSessionAlias(httpRequest)
				:
				unauthenticatedAlias;
		String addAccountUrl = sessionManager.encodeURL(contextPath, addAlias);

		httpRequest.setAttribute("currentAccount", user);
		httpRequest.setAttribute("addAccountUrl", addAccountUrl);
		httpRequest.setAttribute("accounts", users);

		chain.doFilter(request, response);
	}

	public void destroy() {
		log.info("UserSessionFilter destory");
	}

}