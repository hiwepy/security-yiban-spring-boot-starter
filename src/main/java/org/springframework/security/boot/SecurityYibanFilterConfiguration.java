package org.springframework.security.boot;

import java.util.Arrays;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.boot.yiban.authentication.YibanAuthenticationProvider;
import org.springframework.security.boot.yiban.authentication.YibanAuthorizationProcessingFilter;
import org.springframework.security.boot.yiban.authentication.YibanPreAuthenticatedProcessingFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import cn.yiban.open.Authorize;

@Configuration
@AutoConfigureBefore(name = { 
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration"
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityYibanProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityYibanProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityYibanFilterConfiguration {
	
	@Configuration
	@EnableConfigurationProperties({ SecurityYibanProperties.class, SecurityBizProperties.class })
	static class YibanWebSecurityConfigurerAdapter extends SecurityBizConfigurerAdapter {
		
		private AuthenticationManager authenticationManager; 
		private RememberMeServices rememberMeServices;
		private SessionAuthenticationStrategy sessionStrategy;
		
		private final SecurityBizProperties bizProperties;
		private final SecurityYibanProperties yibanProperties;
		
	    private final YibanAuthorizationProcessingFilter yibanAuthorizationProcessingFilter;
		private final YibanPreAuthenticatedProcessingFilter yibanPreAuthenticatedProcessingFilter;
	    private final YibanAuthenticationProvider authenticationProvider;
	    private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
		private final UserDetailsServiceAdapter authcUserDetailsService;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		
		public YibanWebSecurityConfigurerAdapter(
				SecurityBizProperties bizProperties,
				SecurityYibanProperties yibanProperties,
				ObjectProvider<YibanAuthorizationProcessingFilter> yibanAuthorizationProcessingFilter,
				ObjectProvider<YibanPreAuthenticatedProcessingFilter> yibanPreAuthenticatedProcessingFilter,
				ObjectProvider<YibanAuthenticationProvider> yibanAuthenticationProvider,
				ObjectProvider<UserDetailsServiceAdapter> authcUserDetailsService, 
				ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
				@Qualifier("jwtAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				@Qualifier("jwtAuthenticationFailureHandler") ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider) {
			
			super(bizProperties, csrfTokenRepositoryProvider.getIfAvailable());
			
			this.bizProperties = bizProperties;
			this.yibanProperties = yibanProperties;
			this.yibanAuthorizationProcessingFilter = yibanAuthorizationProcessingFilter.getIfAvailable();
			this.yibanPreAuthenticatedProcessingFilter = yibanPreAuthenticatedProcessingFilter.getIfAvailable();
			this.authenticationProvider = yibanAuthenticationProvider.getIfAvailable();
			this.authcUserDetailsService = authcUserDetailsService.getIfAvailable();
			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
		}
		
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
   			AuthenticationManager parentManager = authenticationManager == null ? super.authenticationManagerBean() : authenticationManager;
			ProviderManager authenticationManager = new ProviderManager( Arrays.asList(authenticationProvider), parentManager);
			// 不擦除认证密码，擦除会导致TokenBasedRememberMeServices因为找不到Credentials再调用UserDetailsService而抛出UsernameNotFoundException
			authenticationManager.setEraseCredentialsAfterAuthentication(false);
			return authenticationManager;
		}
		
		@Bean
		public YibanPreAuthenticatedProcessingFilter yibanPreAuthenticatedProcessingFilter(Authorize yibanAuthorize) throws Exception {
	    	
			YibanPreAuthenticatedProcessingFilter authcFilter = new YibanPreAuthenticatedProcessingFilter( yibanAuthorize, 
	        		yibanProperties.getAuthc().getCallback(),
	        		yibanProperties.getAuthc().getState(),
	        		yibanProperties.getAuthc().getDisplay());
			
	        return authcFilter;
	    }
		
		@Bean
		public YibanAuthorizationProcessingFilter authenticationProcessingFilter(Authorize yibanAuthorize,
				@Qualifier("yibanAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
				@Qualifier("yibanAuthenticationFailureHandler") ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler) throws Exception {
	    	
			YibanAuthorizationProcessingFilter authcFilter = new YibanAuthorizationProcessingFilter(yibanAuthorize);

			authcFilter.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
			authcFilter.setAuthenticationFailureHandler(authenticationFailureHandler.getIfAvailable());
			authcFilter.setAuthenticationManager(authenticationManager);
			authcFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler.getIfAvailable());
			authcFilter.setContinueChainBeforeSuccessfulAuthentication(yibanProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication());
			
			if (StringUtils.hasText(yibanProperties.getAuthc().getLoginUrl())) {
				authcFilter.setFilterProcessesUrl(yibanProperties.getAuthc().getLoginUrl());
			}
			authcFilter.setRememberMeServices(rememberMeServices);
			authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
			
	        return authcFilter;
	    }
		
	    @Override
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authenticationProvider);
	        super.configure(auth);
	    }
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {

   	    	//super.configure(http, authcProperties.getCros());
   	    	//super.configure(http, authcProperties.getCsrf());
   	    	//super.configure(http, authcProperties.getHeaders());
	    	super.configure(http);
			
		}

	}
	
}
