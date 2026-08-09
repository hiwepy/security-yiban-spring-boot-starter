package org.springframework.security.boot;

import org.junit.jupiter.api.Test;
import cn.yiban.open.Authorize;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link SecurityYibanAuthcProperties}.
 * @author [@Loong Wan](https://github.com/loong10k)
 */
class SecurityYibanAuthcPropertiesTest {

    @Test
    void defaultValuesShouldBeCorrect() {
        SecurityYibanAuthcProperties props = new SecurityYibanAuthcProperties();
        assertThat(props.getState()).isEqualTo("QUERY");
        assertThat(props.getLoginUrl()).isEqualTo("/login/yiban");
        assertThat(props.getRedirectUrl()).isEqualTo("/");
        assertThat(props.getSuccessUrl()).isEqualTo("/index");
        assertThat(props.getUnauthorizedUrl()).isEqualTo("/error");
        assertThat(props.getFailureUrl()).isEqualTo("/error");
        assertThat(props.getDisplay()).isEqualTo(Authorize.DISPLAY_TAG_T.WEB);
        assertThat(props.isContinueChainBeforeSuccessfulAuthentication()).isTrue();
        assertThat(props.isUseForward()).isFalse();
        assertThat(props.getLogout()).isNotNull();
    }

    @Test
    void prefixShouldBeCorrect() {
        assertThat(SecurityYibanAuthcProperties.PREFIX).isEqualTo("spring.security.yiban.authc");
    }

    @Test
    void appKeyAndSecretShouldBeSettable() {
        SecurityYibanAuthcProperties props = new SecurityYibanAuthcProperties();
        props.setAppKey("test-key");
        props.setAppSecret("test-secret");
        assertThat(props.getAppKey()).isEqualTo("test-key");
        assertThat(props.getAppSecret()).isEqualTo("test-secret");
    }

    @Test
    void callbackShouldBeSettable() {
        SecurityYibanAuthcProperties props = new SecurityYibanAuthcProperties();
        props.setCallback("http://localhost/callback");
        assertThat(props.getCallback()).isEqualTo("http://localhost/callback");
    }

    @Test
    void displayShouldBeSettable() {
        SecurityYibanAuthcProperties props = new SecurityYibanAuthcProperties();
        props.setDisplay(Authorize.DISPLAY_TAG_T.MOBILE);
        assertThat(props.getDisplay()).isEqualTo(Authorize.DISPLAY_TAG_T.MOBILE);
    }

    @Test
    void authorizationParamNameShouldHaveDefault() {
        SecurityYibanAuthcProperties props = new SecurityYibanAuthcProperties();
        assertThat(props.getAuthorizationParamName()).isEqualTo("code");
    }

    @Test
    void ignorePatternsShouldHaveDefault() {
        SecurityYibanAuthcProperties props = new SecurityYibanAuthcProperties();
        assertThat(props.getIgnorePatterns()).containsExactly("code");
    }

}
