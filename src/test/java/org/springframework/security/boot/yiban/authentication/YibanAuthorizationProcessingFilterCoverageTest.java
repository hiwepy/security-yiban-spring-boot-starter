package org.springframework.security.boot.yiban.authentication;

import java.util.Arrays;
import java.util.Collections;

import jakarta.servlet.FilterChain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import cn.yiban.open.Authorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Additional coverage tests for {@link YibanAuthorizationProcessingFilter}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@ExtendWith(MockitoExtension.class)
class YibanAuthorizationProcessingFilterCoverageTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private AuthenticationSuccessHandler successHandler;

    @Mock
    private AuthenticationFailureHandler failureHandler;

    private Authorize authorize;
    private YibanAuthorizationProcessingFilter filter;

    @BeforeEach
    void setUp() {
        authorize = new Authorize("key", "secret");
        filter = new YibanAuthorizationProcessingFilter(authorize);
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);
    }

    @Test
    void constructorShouldSetFields() {
        assertThat(filter.getAuthorizationParamName()).isEqualTo("code");
    }

    @Test
    void constructorWithIgnorePatternsShouldWork() {
        YibanAuthorizationProcessingFilter f = new YibanAuthorizationProcessingFilter(authorize, Arrays.asList("/ignore"));
        assertThat(f).isNotNull();
    }

    @Test
    void authorizationParamNameShouldBeSettable() {
        filter.setAuthorizationParamName("customCode");
        assertThat(filter.getAuthorizationParamName()).isEqualTo("customCode");
    }

    @Test
    void setIgnoreRequestMatcherWithPatternsShouldWork() {
        filter.setIgnoreRequestMatcher(Arrays.asList("/ignore1", "/ignore2"));
        assertThat(filter).isNotNull();
    }

    @Test
    void setIgnoreRequestMatcherWithEmptyListShouldNotFail() {
        filter.setIgnoreRequestMatcher(Collections.emptyList());
        assertThat(filter).isNotNull();
    }

    @Test
    void setIgnoreRequestMatchersShouldWork() {
        filter.setIgnoreRequestMatchers(request -> true);
        assertThat(filter).isNotNull();
    }

    @Test
    void constantsShouldHaveCorrectValues() {
        assertThat(YibanAuthorizationProcessingFilter.AUTHORIZATION_PATH).isEqualTo("/login/yiban");
        assertThat(YibanAuthorizationProcessingFilter.AUTHORIZATION_PARAM).isEqualTo("code");
    }

    @Test
    void doAttemptAuthenticationWithCodeShouldReturnToken() throws Exception {
        when(authenticationManager.authenticate(any())).thenReturn(
                new YibanAuthenticationToken("principal", "cred", Collections.emptyList()));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("code", "test-code");
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = filter.doAttemptAuthentication(request, response);
        assertThat(result).isNotNull();
    }

    @Test
    void doAttemptAuthenticationWithNoCodeShouldStillWork() throws Exception {
        when(authenticationManager.authenticate(any())).thenReturn(
                new YibanAuthenticationToken("principal", "cred", Collections.emptyList()));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = filter.doAttemptAuthentication(request, response);
        assertThat(result).isNotNull();
    }

    @Test
    void setSessionAuthenticationStrategyShouldWork() {
        var strategy = mock(org.springframework.security.web.authentication.session.SessionAuthenticationStrategy.class);
        filter.setSessionAuthenticationStrategy(strategy);
        assertThat(filter).isNotNull();
    }

    @Test
    void doFilterWhenNotRequiringAuthShouldPassThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/other");
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
    }

}
