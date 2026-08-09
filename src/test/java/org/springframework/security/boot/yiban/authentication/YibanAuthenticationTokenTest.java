package org.springframework.security.boot.yiban.authentication;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link YibanAuthenticationToken}.
 * @author [@Loong Wan](https://github.com/loong10k)
 */
class YibanAuthenticationTokenTest {

    @Test
    void constructorWithPrincipalShouldNotBeAuthenticated() {
        YibanAuthenticationToken token = new YibanAuthenticationToken("test-principal");
        assertThat(token.getPrincipal()).isEqualTo("test-principal");
        assertThat(token.getCredentials()).isNull();
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    void constructorWithPrincipalCredentialsAndAuthoritiesShouldBeAuthenticated() {
        var authorities = Collections.<GrantedAuthority>singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        YibanAuthenticationToken token = new YibanAuthenticationToken("principal", "credentials", authorities);
        assertThat(token.getPrincipal()).isEqualTo("principal");
        assertThat(token.getCredentials()).isEqualTo("credentials");
        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getAuthorities()).hasSize(1);
    }

    @Test
    void setAuthenticatedToTrueShouldThrow() {
        YibanAuthenticationToken token = new YibanAuthenticationToken("test");
        assertThatThrownBy(() -> token.setAuthenticated(true))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void setAuthenticatedToFalseShouldWork() {
        YibanAuthenticationToken token = new YibanAuthenticationToken("test");
        token.setAuthenticated(false);
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    void eraseCredentialsShouldClearCredentials() {
        var authorities = Collections.<GrantedAuthority>singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        YibanAuthenticationToken token = new YibanAuthenticationToken("principal", "secret", authorities);
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();
    }

}
