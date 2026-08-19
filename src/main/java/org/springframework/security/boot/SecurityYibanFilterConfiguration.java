package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.boot.utils.WebSecurityUtils;
import org.springframework.security.boot.yiban.authentication.YibanAuthorizationProcessingFilter;
import org.springframework.security.boot.yiban.authentication.YibanPreAuthenticatedProcessingFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import cn.yiban.open.Authorize;

/**
 * Security filter configuration for Yiban authentication.
 * <p>
 * Only active when {@code spring.security.yiban.enabled=true} and running
 * in a servlet web application.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@Configuration
@AutoConfigureBefore(name = {
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration"
})
/**
 * <p>Configuration properties.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityYibanProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityYibanProperties.class, SecurityBizProperties.class })
public class SecurityYibanFilterConfiguration {

	@Configuration
	@EnableConfigurationProperties({ SecurityYibanProperties.class, SecurityYibanAuthcProperties.class, SecurityBizProperties.class })
	static class YibanWebSecurityConfigurerAdapter extends WebSecurityBizConfigurerAdapter {

		private final SecurityYibanAuthcProperties authcProperties;
		private final Authorize yibanAuthorize;

		private final LocaleContextFilter localeContextFilter;
		private final AuthenticationEntryPoint authenticationEntryPoint;
		private final AuthenticationSuccessHandler authenticationSuccessHandler;
		private final AuthenticationFailureHandler authenticationFailureHandler;
		private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;

		public YibanWebSecurityConfigurerAdapter(

				SecurityBizProperties bizProperties,
				SecuritySessionMgtProperties sessionMgtProperties,
				SecurityYibanAuthcProperties authcProperties,

				ObjectProvider<Authorize> authorizeProvider,
				ObjectProvider<LocaleContextFilter> localeContextProvider,
				ObjectProvider<AuthenticationProvider> authenticationProvider,
				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider

				) {

			super(bizProperties, sessionMgtProperties, authenticationProvider.stream().collect(Collectors.toList()));

			this.authcProperties = authcProperties;

			this.yibanAuthorize = authorizeProvider.getIfAvailable();
			this.localeContextFilter = localeContextProvider.getIfAvailable();
			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
			this.authenticationEntryPoint = WebSecurityUtils.authenticationEntryPoint(authcProperties, sessionMgtProperties, authenticationEntryPointProvider.stream().collect(Collectors.toList()));
			this.authenticationSuccessHandler = WebSecurityUtils.authenticationSuccessHandler(authcProperties, sessionMgtProperties, authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
			this.authenticationFailureHandler = WebSecurityUtils.authenticationFailureHandler(authcProperties, sessionMgtProperties, authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
		}

		/**
		 * pre Authenticated Processing Filter.
		 *
		 * @return the result
		 * @throws Exception if an error occurs
		 */
		public YibanPreAuthenticatedProcessingFilter preAuthenticatedProcessingFilter() throws Exception {

			YibanPreAuthenticatedProcessingFilter authcFilter = new YibanPreAuthenticatedProcessingFilter( yibanAuthorize,
					authcProperties.getCallback(),
					authcProperties.getState(),
					authcProperties.getDisplay());

			return authcFilter;
		}

		/**
		 * authentication Processing Filter.
		 *
		 * @return the result
		 * @throws Exception if an error occurs
		 */
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

		/**
		 * configure.
		 *
		 * @param http the http
		 * @throws Exception if an error occurs
		 */
		@Override
		protected void configure(HttpSecurity http) throws Exception {

			http.securityMatcher(authcProperties.getPathPattern())
				.exceptionHandling(configurer -> configurer.authenticationEntryPoint(authenticationEntryPoint))
				.httpBasic(configurer -> configurer.disable())
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
