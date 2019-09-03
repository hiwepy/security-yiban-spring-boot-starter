package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.yiban.SecurityYibanAuthcProperties;

@ConfigurationProperties(prefix = SecurityYibanProperties.PREFIX)
public class SecurityYibanProperties {

	public static final String PREFIX = "spring.security.yiban";

	/** Whether Enable Yiban Authentication. */
	private boolean enabled = false;
	@NestedConfigurationProperty
	private SecurityYibanAuthcProperties authc = new SecurityYibanAuthcProperties();

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public SecurityYibanAuthcProperties getAuthc() {
		return authc;
	}

	public void setAuthc(SecurityYibanAuthcProperties authc) {
		this.authc = authc;
	}

}
