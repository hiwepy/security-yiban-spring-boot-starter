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
package org.springframework.security.boot.yiban.exception;


import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationServiceExceptionAdapter;

/**
 *
 */
@SuppressWarnings("serial")
public class AuthenticationYibanServerException extends AuthenticationServiceExceptionAdapter {
	
	final String code;
	
	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationYibanServerException</code> with the
	 * specified message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationYibanServerException(String code, String msg) {
		super(AuthResponseCode.SC_AUTHZ_THIRD_PARTY_SERVICE, msg);
		this.code = code;
	}

	/**
	 * Constructs an <code>AuthenticationYibanServerException</code> with the
	 * specified message and root cause.
	 *
	 * @param msg the detail message
	 * @param t root cause
	 */
	public AuthenticationYibanServerException(String code, String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_THIRD_PARTY_SERVICE, msg, t);
		this.code = code;
	}
	
	public String getCode() {
		return code;
	}
	
}
