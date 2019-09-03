package org.springframework.security.boot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.yiban.SecurityYibanAuthcProperties;
import org.springframework.security.boot.yiban.authentication.YibanAuthenticationProvider;
import org.springframework.security.boot.yiban.authentication.YibanMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.yiban.authentication.YibanMatchedAuthenticationFailureHandler;
import org.springframework.security.crypto.password.PasswordEncoder;

import cn.yiban.open.Authorize;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityYibanProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityYibanProperties.class })
public class SecurityYibanAutoConfiguration {

	@Autowired
	private SecurityYibanProperties yibanProperties;

	/**
	 *  在程序文件中导入并使用AppID与AppSecret来初始化cn.yiban.open.Authorize
	 */
	@Bean
	public Authorize yibanAuthorize() {
		SecurityYibanAuthcProperties authc = yibanProperties.getAuthc();
		return new Authorize(authc.getAppKey(), authc.getAppSecret());
	}
	
	@Bean
	public YibanMatchedAuthenticationEntryPoint yibanMatchedAuthenticationEntryPoint() {
		return new YibanMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	public YibanMatchedAuthenticationFailureHandler yibanMatchedAuthenticationFailureHandler() {
		return new YibanMatchedAuthenticationFailureHandler();
	}
	
	@Bean
	public YibanAuthenticationProvider idcCodeAuthenticationProvider(
			UserDetailsServiceAdapter userDetailsService, PasswordEncoder passwordEncoder) {
		return new YibanAuthenticationProvider(userDetailsService);
	}
    
}
