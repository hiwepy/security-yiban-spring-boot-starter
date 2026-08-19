/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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
package org.springframework.security.boot.yiban.authentication;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import cn.yiban.open.Authorize;
import cn.yiban.open.Authorize.DISPLAY_TAG_T;

/**
 * <p>Filter for Yiban Pre Authenticated Processing.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class YibanPreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

    private final Authorize authorize;
    private final String redirect_uri;
    private final String state;
    private final Authorize.DISPLAY_TAG_T display;
    
	/**
	 * Constructs a new yiban pre authenticated processing filter instance.
	 *
	 * @param authorize the authorize
	 * @param redirect_uri the redirect_uri
	 * @param state the state
	 * @param display the display
	 */
	public YibanPreAuthenticatedProcessingFilter(Authorize authorize, String redirect_uri, String state,
			DISPLAY_TAG_T display) {
		super();
		this.authorize = authorize;
		this.redirect_uri = redirect_uri;
		this.state = state;
		this.display = display;
	}

	/**
	 * do Filter.
	 *
	 * @param request the request
	 * @param response the response
	 * @param chain the chain
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
			
		String url = authorize.forwardurl(redirect_uri, state, display); 

		// 其中backurl为应用的回调地址，授权服务器授权后会重定向到这个地址。 "QUERY" 为一状态参数，授权服务器原样返回。Authorize.DISPLAY_TAG_T.WEB 标识请求验证的客户端类型。
		WebUtils.getNativeResponse(response, HttpServletResponse.class).sendRedirect(url); 
		
	}

	/**
	 * get Pre Authenticated Principal.
	 *
	 * @param httpRequest the http request
	 * @return the result
	 */
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
		return "N/A";
	}

	/**
	 * get Pre Authenticated Credentials.
	 *
	 * @param httpRequest the http request
	 * @return the result
	 */
	protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
		return "N/A";
	}

}