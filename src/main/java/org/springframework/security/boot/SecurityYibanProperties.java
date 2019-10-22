package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityYibanProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityYibanProperties {

	public static final String PREFIX = "spring.security.yiban";

	/** Whether Enable Yiban Authentication. */
	private boolean enabled = false;
	
}
