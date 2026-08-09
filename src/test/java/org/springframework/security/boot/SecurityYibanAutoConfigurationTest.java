package org.springframework.security.boot;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.yiban.authentication.YibanAuthenticationProvider;
import org.springframework.security.boot.yiban.authentication.YibanMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.yiban.authentication.YibanMatchedAuthenticationFailureHandler;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import cn.yiban.open.Authorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link SecurityYibanAutoConfiguration}.
 * @author [@Loong Wan](https://github.com/loong10k)
 */
class SecurityYibanAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SecurityYibanAutoConfiguration.class))
            .withBean(PasswordEncoder.class, () -> mock(PasswordEncoder.class))
            .withBean(UserDetailsServiceAdapter.class, () -> mock(UserDetailsServiceAdapter.class));

    @Test
    void whenEnabledThenBeansAreCreated() {
        contextRunner
                .withPropertyValues("spring.security.yiban.enabled=true",
                        "spring.security.yiban.authc.appKey=testKey",
                        "spring.security.yiban.authc.appSecret=testSecret")
                .run(context -> {
                    assertThat(context).hasSingleBean(Authorize.class);
                    assertThat(context).hasSingleBean(SecurityContextLogoutHandler.class);
                    assertThat(context).hasSingleBean(YibanMatchedAuthenticationEntryPoint.class);
                    assertThat(context).hasSingleBean(YibanMatchedAuthenticationFailureHandler.class);
                    assertThat(context).hasSingleBean(YibanAuthenticationProvider.class);
                });
    }

    @Test
    void whenNotEnabledThenNoBeans() {
        contextRunner
                .withPropertyValues("spring.security.yiban.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(Authorize.class);
                    assertThat(context).doesNotHaveBean(YibanAuthenticationProvider.class);
                });
    }

}
