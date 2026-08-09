package org.springframework.security.boot.yiban.authentication;

import java.util.Collections;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;

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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for the doFilter method of {@link YibanAuthorizationProcessingFilter}.
 * @author [@Loong Wan](https://github.com/loong10k)
 */
@ExtendWith(MockitoExtension.class)
class YibanAuthorizationDoFilterTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private AuthenticationSuccessHandler successHandler;

    @Mock
    private AuthenticationFailureHandler failureHandler;

    @Mock
    private FilterChain chain;

    private YibanAuthorizationProcessingFilter filter;

    @BeforeEach
    void setUp() {
        Authorize authorize = new Authorize("key", "secret");
        filter = new YibanAuthorizationProcessingFilter(authorize);
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);
        // Set the request matcher to always match
        filter.setRequiresAuthenticationRequestMatcher(request -> true);
    }

    @Test
    void doFilterWhenAuthSucceedsShouldCallSuccessAndChain() throws Exception {
        YibanAuthenticationToken authResult = new YibanAuthenticationToken("principal", "cred", Collections.emptyList());
        when(authenticationManager.authenticate(any())).thenReturn(authResult);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("code", "test-code");
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(successHandler).onAuthenticationSuccess(any(), any(), any());
        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilterWhenAuthFailsShouldCallFailureHandler() throws Exception {
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("code", "test-code");
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(failureHandler).onAuthenticationFailure(any(), any(), any());
    }

    @Test
    void doFilterWhenAuthReturnsNullShouldReturn() throws Exception {
        when(authenticationManager.authenticate(any())).thenReturn(null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("code", "test-code");
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verifyNoInteractions(successHandler);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void doFilterWhenInternalErrorShouldCallFailure() throws Exception {
        when(authenticationManager.authenticate(any())).thenThrow(
                new org.springframework.security.authentication.InternalAuthenticationServiceException("internal error"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("code", "test-code");
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(failureHandler).onAuthenticationFailure(any(), any(), any());
    }

}
