package org.springframework.security.boot.yiban.authentication;

import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.yiban.userdetails.YibanPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link YibanAuthenticationProvider}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@ExtendWith(MockitoExtension.class)
class YibanAuthenticationProviderTest {

    @Mock
    private UserDetailsServiceAdapter userDetailsService;

    private YibanAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        provider = new YibanAuthenticationProvider(userDetailsService);
    }

    @Test
    void supportsYibanAuthenticationTokenShouldReturnTrue() {
        assertThat(provider.supports(YibanAuthenticationToken.class)).isTrue();
    }

    @Test
    void supportsOtherTokenClassShouldReturnFalse() {
        assertThat(provider.supports(org.springframework.security.authentication.UsernamePasswordAuthenticationToken.class)).isFalse();
    }

    @Test
    void authenticateWithNullAuthenticationShouldThrow() {
        assertThatThrownBy(() -> provider.authenticate(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getUserDetailsServiceShouldReturnInjectedService() {
        assertThat(provider.getUserDetailsService()).isEqualTo(userDetailsService);
    }

    @Test
    void userDetailsCheckerShouldBeSettable() {
        var checker = new org.springframework.security.authentication.AccountStatusUserDetailsChecker();
        provider.setUserDetailsChecker(checker);
        assertThat(provider.getUserDetailsChecker()).isEqualTo(checker);
    }

}
