package com.springcloud.session.oauth2.service;

import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;

import javax.sql.DataSource;

/**
 * 自定义JdbcClientDetails 继承JdbcClientDetailsService
 * @author xienjiang
 * @createdAt 2016.2.28
 */
public class CustomJdbcClientDetailsService extends JdbcClientDetailsService {

    private static final String SELECT_CLIENT_DETAILS_SQL = "select client_id, client_secret,resource_ids, scope ,authorized_grant_types, " +
            "redirect_uri,authorities,expire_in,assign_time,callback_url,auto_approve " +
            "from oauth_client_details where client_id = ?";


    public CustomJdbcClientDetailsService(DataSource dataSource) {
        super(dataSource);

        setSelectClientDetailsSql(SELECT_CLIENT_DETAILS_SQL);
    }

}
