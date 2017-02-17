package com.springcloud.session.security.test.rest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.session.ExpiringSession;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:spring/spring-context.xml")
@WebAppConfiguration
public class RestMockMvcTests {

	@Autowired
	SessionRepositoryFilter<? extends ExpiringSession> sessionRepositoryFilter;

	@Autowired
	WebApplicationContext context;

	MockMvc mvc;


	@Before
	public void setup() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context).alwaysDo(print())
				.addFilters(this.sessionRepositoryFilter).apply(springSecurity()).build();
	}

	@Test
	public void noSessionOnNoCredentials() throws Exception {
		this.mvc.perform(get("http://localhost:8080/login")).andExpect(header().doesNotExist("x-auth-token"))
				.andExpect(status().isUnauthorized());
	}

	@WithMockUser
	@Test
	public void autheticatedAnnotation() throws Exception {
		this.mvc.perform(get("/")).andExpect(content().string("{\"username\":\"user\"}"));

	}

	@Test
	public void autheticatedRequestPostProcessor() throws Exception {
		this.mvc.perform(get("/").with(user("user")))
				.andExpect(content().string("{\"username\":\"user\"}"));

	}
}
