package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.yiban.authentication.YibanAuthenticationProvider;
import org.springframework.security.boot.yiban.authentication.YibanMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.yiban.authentication.YibanMatchedAuthenticationFailureHandler;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;

import cn.yiban.open.Authorize;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityYibanProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityYibanProperties.class })
public class SecurityYibanAutoConfiguration {

	/**
	 * 在程序文件中导入并使用AppID与AppSecret来初始化cn.yiban.open.Authorize
	 */
	@Bean
	public Authorize yibanAuthorize(SecurityYibanAuthcProperties authcProperties) {
		return new Authorize(authcProperties.getAppKey(), authcProperties.getAppSecret());
	}

	@Bean("yibanInvalidSessionStrategy")
	public InvalidSessionStrategy yibanInvalidSessionStrategy(SecurityYibanAuthcProperties authcProperties) {
		SimpleRedirectInvalidSessionStrategy invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
				authcProperties.getRedirectUrl());
		invalidSessionStrategy.setCreateNewSession(authcProperties.getSessionMgt().isAllowSessionCreation());
		return invalidSessionStrategy;
	}

	@Bean("yibanExpiredSessionStrategy")
	public SessionInformationExpiredStrategy yibanExpiredSessionStrategy(SecurityYibanAuthcProperties authcProperties, RedirectStrategy redirectStrategy) {
		return new SimpleRedirectSessionInformationExpiredStrategy(authcProperties.getRedirectUrl(),
				redirectStrategy);
	}

	@Bean("yibanSecurityContextLogoutHandler")
	public SecurityContextLogoutHandler yibanSecurityContextLogoutHandler(SecurityYibanAuthcProperties authcProperties) {

		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setClearAuthentication(authcProperties.getLogout().isClearAuthentication());
		logoutHandler.setInvalidateHttpSession(authcProperties.getLogout().isInvalidateHttpSession());

		return logoutHandler;
	}
 

	@Bean
	@ConditionalOnMissingBean
	public YibanMatchedAuthenticationEntryPoint yibanMatchedAuthenticationEntryPoint() {
		return new YibanMatchedAuthenticationEntryPoint();
	}

	@Bean
	@ConditionalOnMissingBean
	public YibanMatchedAuthenticationFailureHandler yibanMatchedAuthenticationFailureHandler() {
		return new YibanMatchedAuthenticationFailureHandler();
	}

	@Bean
	public YibanAuthenticationProvider yibanAuthenticationProvider(UserDetailsServiceAdapter userDetailsService,
			PasswordEncoder passwordEncoder) {
		return new YibanAuthenticationProvider(userDetailsService);
	}

}
