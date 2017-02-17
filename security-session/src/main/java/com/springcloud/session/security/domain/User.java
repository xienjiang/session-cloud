package com.springcloud.session.security.domain;

/**
 * 用户
 * @author JohnnyJiang
 * @since 2017.02.14
 */
public class User {
    private String username;

	private String logoutUrl;

	private String switchAccountUrl;

	public User(String username, String logoutUrl, String switchAccountUrl) {
		super();
		this.username = username;
		this.logoutUrl = logoutUrl;
		this.switchAccountUrl = switchAccountUrl;
	}

	public String getUsername() {
		return this.username;
	}

	public String getLogoutUrl() {
		return this.logoutUrl;
	}

	public String getSwitchAccountUrl() {
		return this.switchAccountUrl;
	}

}