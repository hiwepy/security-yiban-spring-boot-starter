package org.springframework.security.boot;

import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link SecurityYibanFilterConfiguration}.
 * @author [@Loong Wan](https://github.com/loong10k)
 */
class SecurityYibanFilterConfigurationTest {

    @Test
    void sessionMgtPropertiesShouldHaveDefaults() {
        SecuritySessionMgtProperties props = new SecuritySessionMgtProperties();
        assertThat(props.isAllowSessionCreation()).isTrue();
        assertThat(props.getFailureUrl()).isEqualTo("/error");
        assertThat(props.getMaximumSessions()).isEqualTo(1);
        assertThat(props.isMaxSessionsPreventsLogin()).isFalse();
        assertThat(props.getSessionAttrName()).isEqualTo("SPRING_SECURITY_SAVED_REQUEST");
        assertThat(props.getFixationPolicy()).isNotNull();
        assertThat(props.getCreationPolicy()).isNotNull();
        assertThat(props.getRemember()).isNotNull();
        assertThat(props.getLogout()).isNotNull();
    }

    @Test
    void filterConfigurationClassShouldExist() {
        // Verify the class is loadable and has expected annotations
        assertThat(SecurityYibanFilterConfiguration.class).isNotNull();
        assertThat(SecurityYibanFilterConfiguration.class.getAnnotations()).isNotEmpty();
    }

    @Test
    void yibanWebSecurityConfigurerAdapterShouldBeInnerClass() {
        Class<?>[] innerClasses = SecurityYibanFilterConfiguration.class.getDeclaredClasses();
        assertThat(innerClasses).hasSize(1);
        assertThat(innerClasses[0].getSimpleName()).isEqualTo("YibanWebSecurityConfigurerAdapter");
    }

}
