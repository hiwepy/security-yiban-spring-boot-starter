package org.springframework.security.boot.yiban.authentication;

import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.springframework.security.web.util.matcher.RequestMatcher;
import cn.yiban.open.Authorize;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link YibanAuthorizationProcessingFilter}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class YibanAuthorizationProcessingFilterTest {

    @Test
    void constructorShouldSetAuthorize() {
        Authorize authorize = new Authorize("key", "secret");
        YibanAuthorizationProcessingFilter filter = new YibanAuthorizationProcessingFilter(authorize);
        assertThat(filter.getAuthorizationParamName()).isEqualTo("code");
    }

    @Test
    void constructorWithIgnorePatternsShouldWork() {
        Authorize authorize = new Authorize("key", "secret");
        YibanAuthorizationProcessingFilter filter = new YibanAuthorizationProcessingFilter(authorize, Arrays.asList("/ignore"));
        assertThat(filter).isNotNull();
    }

    @Test
    void authorizationParamNameShouldBeSettable() {
        Authorize authorize = new Authorize("key", "secret");
        YibanAuthorizationProcessingFilter filter = new YibanAuthorizationProcessingFilter(authorize);
        filter.setAuthorizationParamName("customCode");
        assertThat(filter.getAuthorizationParamName()).isEqualTo("customCode");
    }

    @Test
    void setIgnoreRequestMatcherWithPatternsShouldWork() {
        Authorize authorize = new Authorize("key", "secret");
        YibanAuthorizationProcessingFilter filter = new YibanAuthorizationProcessingFilter(authorize);
        filter.setIgnoreRequestMatcher(Arrays.asList("/ignore1", "/ignore2"));
        assertThat(filter).isNotNull();
    }

    @Test
    void setIgnoreRequestMatcherWithEmptyListShouldNotFail() {
        Authorize authorize = new Authorize("key", "secret");
        YibanAuthorizationProcessingFilter filter = new YibanAuthorizationProcessingFilter(authorize);
        filter.setIgnoreRequestMatcher(Collections.emptyList());
        assertThat(filter).isNotNull();
    }

    @Test
    void setIgnoreRequestMatchersShouldWork() {
        Authorize authorize = new Authorize("key", "secret");
        YibanAuthorizationProcessingFilter filter = new YibanAuthorizationProcessingFilter(authorize);
        filter.setIgnoreRequestMatchers(request -> true);
        assertThat(filter).isNotNull();
    }

    @Test
    void constantsShouldHaveCorrectValues() {
        assertThat(YibanAuthorizationProcessingFilter.AUTHORIZATION_PATH).isEqualTo("/login/yiban");
        assertThat(YibanAuthorizationProcessingFilter.AUTHORIZATION_PARAM).isEqualTo("code");
    }

}
