package com.springcloud.session.oauth2.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CustomUserDetails implements UserDetails {

    private static final long serialVersionUID = 3957586021470480642L;

    protected static final String ROLE_PREFIX = "ROLE_";
    protected static final GrantedAuthority DEFAULT_USER_ROLE = new SimpleGrantedAuthority(ROLE_PREFIX + Privilege.API.name());

    protected User user;
    
    protected List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
    

    public CustomUserDetails() {}

    public CustomUserDetails(User user) {
        this.user = user;
        initialAuthorities();
    }
    
    private void initialAuthorities() {
        this.grantedAuthorities.add(DEFAULT_USER_ROLE);
        final List<Privilege> privileges = user.getPrivileges();
        for (Privilege privilege : privileges) {
            this.grantedAuthorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + privilege.name()));
        }
    }
    
    private void initialWeimobUserAuthorities() {
        this.grantedAuthorities.add(DEFAULT_USER_ROLE);
    }

    /**
     * Return authorities, more information see {@link #initialAuthorities()}
     *
     * @return Collection of GrantedAuthority
     */
    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return this.grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return this.user.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public User user() {
        return user;
    }
    

	@Override
	public String toString() {
		return "CustomUserDetails [user=" + user + ", grantedAuthorities="
				+ grantedAuthorities + "]";
	}



   
}