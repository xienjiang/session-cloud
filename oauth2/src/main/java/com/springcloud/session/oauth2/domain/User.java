package com.springcloud.session.oauth2.domain;

import com.springcloud.session.oauth2.domain.Privilege;
import lombok.Data;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Data
public class User implements Serializable {

    private static final long serialVersionUID = -426815489585947673L;

    protected int userId;
    private String userName;
    private String password;

    private String phone;
    private String email;

    private Date lastLoginTime;

    private Date createTime;

    private List<Privilege> privileges = new ArrayList<>();

    public User(String userName,String password){
        this.userName = userName;
        this.password = password;
    }
}
    
    
    
