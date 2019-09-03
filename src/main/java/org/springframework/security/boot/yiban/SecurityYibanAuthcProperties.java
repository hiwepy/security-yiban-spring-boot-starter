/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.yiban;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.boot.yiban.authentication.YibanAuthorizationProcessingFilter;
import org.springframework.security.core.Authentication;

import cn.yiban.open.Authorize;
import lombok.Data;

@Data
public class SecurityYibanAuthcProperties {

	public static final String PREFIX = "spring.security.yiban.authc";

	/**
	 * 接入应用 APPID
	 */
	private String appKey;

	/**
	 * 接入应用的 AppSecret
	 */
	private String appSecret;
	private String callback;

	private String redirect_uri;
	private String state = "QUERY";

	private Authorize.DISPLAY_TAG_T display = Authorize.DISPLAY_TAG_T.WEB;

	private String authorizationParamName = YibanAuthorizationProcessingFilter.AUTHORIZATION_PARAM;

	private boolean allowSessionCreation = false;
	
	/** Authorization Path Pattern */
	private String pathPattern = YibanAuthorizationProcessingFilter.AUTHORIZATION_PARAM;
	
	private String[] ignorePatterns = new String[] { YibanAuthorizationProcessingFilter.AUTHORIZATION_PARAM };

	/**
	 * Indicates if the filter chain should be continued prior to delegation to
	 * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)}
	 * , which may be useful in certain environment (such as Tapestry applications).
	 * Defaults to <code>false</code>.
	 */
	private boolean continueChainBeforeSuccessfulAuthentication = true;
	
}
