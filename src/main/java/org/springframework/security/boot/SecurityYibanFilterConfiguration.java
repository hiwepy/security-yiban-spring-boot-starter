package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.boot.yiban.authentication.YibanAuthorizationProcessingFilter;
import org.springframework.security.boot.yiban.authentication.YibanPreAuthenticatedProcessingFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;

import com.fasterxml.jackson.databind.ObjectMapper;

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
	@EnableConfigurationProperties({ SecurityYibanProperties.class, SecurityYibanAuthcProperties.class, SecurityBizProperties.class })
	static class YibanWebSecurityConfigurerAdapter extends WebSecurityBizConfigurerAdapter {
		
		private final SecurityYibanAuthcProperties authcProperties;

    	private final LocaleContextFilter localeContextFilter;
	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
	    private final Authorize yibanAuthorize;
    	private final RequestCache requestCache;
    	private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		
		public YibanWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
				SecuritySessionMgtProperties sessionMgtProperties,
				SecurityYibanAuthcProperties authcProperties,

   				ObjectProvider<LocaleContextFilter> localeContextProvider,
				ObjectProvider<Authorize> authorizeProvider,
				ObjectProvider<AuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider
				
				) {
			
			super(bizProperties, authcProperties, sessionMgtProperties, authenticationProvider.stream().collect(Collectors.toList()),
					authenticationManagerProvider.getIfAvailable());
			
			this.authcProperties = authcProperties;

			this.localeContextFilter = localeContextProvider.getIfAvailable();
			this.yibanAuthorize = authorizeProvider.getIfAvailable();
			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
   			this.authenticationEntryPoint = super.authenticationEntryPoint(authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = super.authenticationSuccessHandler(authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
   			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
   			this.requestCache = super.requestCache();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = super.sessionAuthenticationStrategy();
		}
		
		public YibanPreAuthenticatedProcessingFilter preAuthenticatedProcessingFilter() throws Exception {
	    	
			YibanPreAuthenticatedProcessingFilter authcFilter = new YibanPreAuthenticatedProcessingFilter( yibanAuthorize, 
	        		authcProperties.getCallback(),
	        		authcProperties.getState(),
	        		authcProperties.getDisplay());
			
	        return authcFilter;
	    }
		
		public YibanAuthorizationProcessingFilter authenticationProcessingFilter() throws Exception {
	    	
			YibanAuthorizationProcessingFilter authcFilter = new YibanAuthorizationProcessingFilter(yibanAuthorize);

			authcFilter.setAllowSessionCreation(getSessionMgtProperties().isAllowSessionCreation());
			authcFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
			authcFilter.setAuthenticationManager(authenticationManagerBean());
			authcFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
			authcFilter.setContinueChainBeforeSuccessfulAuthentication(authcProperties.isContinueChainBeforeSuccessfulAuthentication());
			
			if (StringUtils.hasText(authcProperties.getLoginUrl())) {
				authcFilter.setFilterProcessesUrl(authcProperties.getLoginUrl());
			}
			authcFilter.setRememberMeServices(rememberMeServices);
			authcFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
			
	        return authcFilter;
	    }
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {

			http.requestCache()
	        	.requestCache(requestCache)
	        	.and()
	        	.exceptionHandling()
	        	.authenticationEntryPoint(authenticationEntryPoint)
	        	.and()
	        	.httpBasic()
	        	.disable()
	        	.antMatcher(authcProperties.getPathPattern())
	        	.addFilterBefore(localeContextFilter, UsernamePasswordAuthenticationFilter.class)
	        	.addFilterBefore(preAuthenticatedProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
	        	.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class); 
	    	
	    	super.configure(http, authcProperties.getCors());
	    	super.configure(http, authcProperties.getCsrf());
	    	super.configure(http, authcProperties.getHeaders());
    	super.configure(http);
			
		}

	}
	
}
