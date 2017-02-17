package com.springcloud.session.security.initializer;


import com.springcloud.session.security.config.SpringSecurityConfig;
import com.springcloud.session.security.filter.UserSessionFilter;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

import javax.servlet.ServletContext;

/**
 * 用于spring security初始化时加载session相关配置属性，这里采用的是实现SecurityInitializer，
 * 这里确保的是springSessionRepositoryFilter会在springSecurityFilterChain之前被调用，从而使得web容器(如tomcat)使用上spring-session过滤器
 * @author JohnnyJiang
 * @since 2017.02.13
 */
public class SecurityInitializer extends AbstractSecurityWebApplicationInitializer {

        public SecurityInitializer() {
                super(SpringSecurityConfig.class);
        }

        @Override
        protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
                appendFilters(servletContext, new UserSessionFilter());
                super.afterSpringSecurityFilterChain(servletContext);

        }


}