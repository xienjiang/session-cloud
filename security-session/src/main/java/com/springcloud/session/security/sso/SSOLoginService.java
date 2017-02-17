package com.springcloud.session.security.sso;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.HttpSessionManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * SSO 登陆服务
 */
@Slf4j
public class SSOLoginService {

        public static void doSSOLogin(HttpServletRequest httpRequest) {
            HttpSessionManager sessionManager =(HttpSessionManager) httpRequest.getAttribute(HttpSessionManager.class.getName());
            String alias = httpRequest.getParameter("_s");

            SessionRepository<Session> sessionRepository =
            (SessionRepository<Session>) httpRequest.getAttribute(SessionRepository.class.getName());
            for(Map.Entry<String, String> entry : sessionManager.getSessionIds(httpRequest).entrySet()) {
                String aliasId = entry.getKey();
                String sessionValue = entry.getValue();
                Session session = sessionRepository.getSession(sessionValue);
                HttpSession httpSession = httpRequest.getSession();
                if(session != null && session.getAttribute("username") != null && httpSession.getAttribute("username") == null ) {
                    httpSession.setAttribute("username", session.getAttribute("username"));
                }

                log.info("[SSOLoginService] doSSOLogin aliasId {} : session value{}",aliasId,sessionValue);
            }

            if(StringUtils.isEmpty(alias)) {
                alias = sessionManager.getNewSessionAlias(httpRequest);
            }
            
            httpRequest.setAttribute("alias",alias);
        }
    }