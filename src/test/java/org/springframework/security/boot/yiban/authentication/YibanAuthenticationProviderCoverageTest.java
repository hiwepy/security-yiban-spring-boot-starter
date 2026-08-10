package org.springframework.security.boot.yiban.authentication;

import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.yiban.userdetails.YibanPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Additional coverage tests for {@link YibanAuthenticationProvider}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@ExtendWith(MockitoExtension.class)
class YibanAuthenticationProviderCoverageTest {

    @Mock
    private UserDetailsServiceAdapter userDetailsService;

    private YibanAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        provider = new YibanAuthenticationProvider(userDetailsService);
    }

    @Test
    void authenticateWithValidTokenShouldReturnAuthenticatedToken() {
        YibanPrincipal principal = new YibanPrincipal("user", "pass", "ROLE_USER");
        when(userDetailsService.loadUserDetails(any(org.springframework.security.core.Authentication.class))).thenReturn(principal);

        YibanAuthenticationToken request = new YibanAuthenticationToken("valid-token");
        request.setDetails("details");
        Authentication result = provider.authenticate(request);

        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isInstanceOf(SecurityPrincipal.class);
    }

    @Test
    void authenticateWithNonPrincipalUserShouldReturnUsernameToken() {
        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                "user", "pass", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        when(userDetailsService.loadUserDetails(any(org.springframework.security.core.Authentication.class))).thenReturn(userDetails);

        YibanAuthenticationToken request = new YibanAuthenticationToken("valid-token");
        Authentication result = provider.authenticate(request);

        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isEqualTo("user");
    }

    @Test
    void supportsShouldReturnTrueForYibanToken() {
        assertThat(provider.supports(YibanAuthenticationToken.class)).isTrue();
    }

    @Test
    void supportsShouldReturnFalseForOtherToken() {
        assertThat(provider.supports(org.springframework.security.authentication.UsernamePasswordAuthenticationToken.class)).isFalse();
    }

}
