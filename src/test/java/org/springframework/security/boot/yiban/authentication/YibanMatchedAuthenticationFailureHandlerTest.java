package org.springframework.security.boot.yiban.authentication;

import java.io.IOException;

import jakarta.servlet.ServletException;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.yiban.exception.AuthenticationYibanServerException;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link YibanMatchedAuthenticationFailureHandler}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class YibanMatchedAuthenticationFailureHandlerTest {

    private final YibanMatchedAuthenticationFailureHandler handler = new YibanMatchedAuthenticationFailureHandler();

    @Test
    void supportsYibanExceptionShouldReturnTrue() {
        AuthenticationYibanServerException ex = new AuthenticationYibanServerException("E001", "yiban error");
        assertThat(handler.supports(ex)).isTrue();
    }

    @Test
    void supportsOtherExceptionShouldReturnFalse() {
        AuthenticationException ex = new AuthenticationException("other") {};
        assertThat(handler.supports(ex)).isFalse();
    }

    @Test
    void onAuthenticationFailureWithYibanExceptionShouldWriteJsonResponse() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationYibanServerException ex = new AuthenticationYibanServerException("E001", "yiban error");

        handler.onAuthenticationFailure(request, response, ex);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).contains("application/json");
        assertThat(response.getContentAsString()).contains("yiban error");
    }

    @Test
    void onAuthenticationFailureWithOtherExceptionShouldWriteDefaultErrorResponse() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException ex = new AuthenticationException("other error") {};

        handler.onAuthenticationFailure(request, response, ex);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsString()).isNotEmpty();
    }

}
