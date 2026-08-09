package org.springframework.security.boot.yiban.userdetails;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link YibanPrincipal}.
 * @author [@Loong Wan](https://github.com/loong10k)
 */
class YibanPrincipalTest {

    @Test
    void constructorWithRolesShouldCreatePrincipal() {
        YibanPrincipal principal = new YibanPrincipal("user", "pass", "ROLE_USER");
        assertThat(principal.getUsername()).isEqualTo("user");
        assertThat(principal.getPassword()).isEqualTo("pass");
        assertThat(principal.getAuthorities()).hasSize(1);
    }

    @Test
    void constructorWithAuthoritiesShouldCreatePrincipal() {
        var authorities = Collections.<GrantedAuthority>singletonList(new SimpleGrantedAuthority("ROLE_ADMIN"));
        YibanPrincipal principal = new YibanPrincipal("user", "pass", authorities);
        assertThat(principal.getUsername()).isEqualTo("user");
    }

    @Test
    void constructorWithAllFlagsShouldWork() {
        var authorities = Collections.<GrantedAuthority>singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        YibanPrincipal principal = new YibanPrincipal("user", "pass", true, true, true, true, authorities);
        assertThat(principal.isEnabled()).isTrue();
        assertThat(principal.isAccountNonExpired()).isTrue();
    }

    @Test
    void ybUidGetterSetterShouldWork() {
        YibanPrincipal principal = new YibanPrincipal("user", "pass", "ROLE_USER");
        principal.setYbUid("uid123");
        assertThat(principal.getYbUid()).isEqualTo("uid123");
    }

    @Test
    void moneyGetterSetterShouldWork() {
        YibanPrincipal principal = new YibanPrincipal("user", "pass", "ROLE_USER");
        principal.setMoney("100");
        assertThat(principal.getMoney()).isEqualTo("100");
    }

    @Test
    void expGetterSetterShouldWork() {
        YibanPrincipal principal = new YibanPrincipal("user", "pass", "ROLE_USER");
        principal.setExp("500");
        assertThat(principal.getExp()).isEqualTo("500");
    }

    @Test
    void userheadGetterSetterShouldWork() {
        YibanPrincipal principal = new YibanPrincipal("user", "pass", "ROLE_USER");
        principal.setUserhead("http://img.example.com/avatar.jpg");
        assertThat(principal.getUserhead()).isEqualTo("http://img.example.com/avatar.jpg");
    }

    @Test
    void schoolidGetterSetterShouldWork() {
        YibanPrincipal principal = new YibanPrincipal("user", "pass", "ROLE_USER");
        principal.setSchoolid("school001");
        assertThat(principal.getSchoolid()).isEqualTo("school001");
    }

    @Test
    void schoolnameGetterSetterShouldWork() {
        YibanPrincipal principal = new YibanPrincipal("user", "pass", "ROLE_USER");
        principal.setSchoolname("Test University");
        assertThat(principal.getSchoolname()).isEqualTo("Test University");
    }

}
