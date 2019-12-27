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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import cn.yiban.open.Authorize;
import cn.yiban.open.Authorize.DISPLAY_TAG_T;

public class YibanPreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

    private final Authorize authorize;
    private final String redirect_uri;
    private final String state;
    private final Authorize.DISPLAY_TAG_T display;
    
	public YibanPreAuthenticatedProcessingFilter(Authorize authorize, String redirect_uri, String state,
			DISPLAY_TAG_T display) {
		super();
		this.authorize = authorize;
		this.redirect_uri = redirect_uri;
		this.state = state;
		this.display = display;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
			
		String url = authorize.forwardurl(redirect_uri, state, display); 

		// 其中backurl为应用的回调地址，授权服务器授权后会重定向到这个地址。 "QUERY" 为一状态参数，授权服务器原样返回。Authorize.DISPLAY_TAG_T.WEB 标识请求验证的客户端类型。
		WebUtils.getNativeResponse(response, HttpServletResponse.class).sendRedirect(url); 
		
	}

	protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
		return "N/A";
	}

	protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
		return "N/A";
	}

}