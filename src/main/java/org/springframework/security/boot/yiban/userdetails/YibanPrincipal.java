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
package org.springframework.security.boot.yiban.userdetails;

import java.util.Collection;

import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.core.GrantedAuthority;

/**
 *      易班用户基本信息
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class YibanPrincipal extends SecurityPrincipal {

	/**
	 * 易班用户id
	 */
	protected String ybUid;
	/**
	 *持有网薪
	 */
	protected String money;
	/**
	 * 经验值
	 */
	protected String exp;
	/**
	 * 用户头像
	 */
	protected String userhead;
	/**
	 * 所在学校id
	 */
	protected String schoolid;
	/**
	 * 所在学校名称
	 */
	protected String schoolname;
	/**
	 * 真实姓名
	 */
	protected String realname;
	/**
	 * 生日
	 */
	protected String birthday;
	/**
	 * 学校首选认证类型编号：如对认证信息的类型敏感，该字段建议使用user/verify_me接口代替
	 */
	protected String studentid;
	/**
	 * 枚举，学生、老师、辅导员、未认证
	 */
	protected String identity;
	
	/**
	 * Constructs a new yiban principal instance.
	 *
	 * @param username the username
	 * @param password the password
	 * @param roles the roles
	 */
	public YibanPrincipal(String username, String password, String... roles) {
		super(username, password, roles);
	}

	/**
	 * Constructs a new yiban principal instance.
	 *
	 * @param username the username
	 * @param password the password
	 * @param authorities the authorities
	 */
	public YibanPrincipal(String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
	}

	/**
	 * Constructs a new yiban principal instance.
	 *
	 * @param username the username
	 * @param password the password
	 * @param enabled the enabled
	 * @param accountNonExpired the account non expired
	 * @param credentialsNonExpired the credentials non expired
	 * @param accountNonLocked the account non locked
	 * @param authorities the authorities
	 */
	public YibanPrincipal(String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
	}

	/**
	 * Returns the yb uid.
	 *
	 * @return the yb uid
	 */
	public String getYbUid() {
		return ybUid;
	}

	/**
	 * Sets the yb uid.
	 *
	 * @param ybUid the yb uid
	 */
	public void setYbUid(String ybUid) {
		this.ybUid = ybUid;
	}

	/**
	 * Returns the money.
	 *
	 * @return the money
	 */
	public String getMoney() {
		return money;
	}

	/**
	 * Sets the money.
	 *
	 * @param money the money
	 */
	public void setMoney(String money) {
		this.money = money;
	}

	/**
	 * Returns the exp.
	 *
	 * @return the exp
	 */
	public String getExp() {
		return exp;
	}

	/**
	 * Sets the exp.
	 *
	 * @param exp the exp
	 */
	public void setExp(String exp) {
		this.exp = exp;
	}

	/**
	 * Returns the userhead.
	 *
	 * @return the userhead
	 */
	public String getUserhead() {
		return userhead;
	}

	/**
	 * Sets the userhead.
	 *
	 * @param userhead the userhead
	 */
	public void setUserhead(String userhead) {
		this.userhead = userhead;
	}

	/**
	 * Returns the schoolid.
	 *
	 * @return the schoolid
	 */
	public String getSchoolid() {
		return schoolid;
	}

	/**
	 * Sets the schoolid.
	 *
	 * @param schoolid the schoolid
	 */
	public void setSchoolid(String schoolid) {
		this.schoolid = schoolid;
	}

	/**
	 * Returns the schoolname.
	 *
	 * @return the schoolname
	 */
	public String getSchoolname() {
		return schoolname;
	}

	/**
	 * Sets the schoolname.
	 *
	 * @param schoolname the schoolname
	 */
	public void setSchoolname(String schoolname) {
		this.schoolname = schoolname;
	}

}
