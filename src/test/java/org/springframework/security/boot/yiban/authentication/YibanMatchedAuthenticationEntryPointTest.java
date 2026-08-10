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
 * Tests for {@link YibanMatchedAuthenticationEntryPoint}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class YibanMatchedAuthenticationEntryPointTest {

    private final YibanMatchedAuthenticationEntryPoint entryPoint = new YibanMatchedAuthenticationEntryPoint();

    @Test
    void supportsYibanExceptionShouldReturnTrue() {
        AuthenticationYibanServerException ex = new AuthenticationYibanServerException("E001", "yiban error");
        assertThat(entryPoint.supports(ex)).isTrue();
    }

    @Test
    void supportsOtherExceptionShouldReturnFalse() {
        AuthenticationException ex = new AuthenticationException("other") {};
        assertThat(entryPoint.supports(ex)).isFalse();
    }

    @Test
    void commenceWithYibanExceptionShouldWriteJsonResponse() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationYibanServerException ex = new AuthenticationYibanServerException("E001", "yiban error");

        entryPoint.commence(request, response, ex);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).contains("application/json");
        assertThat(response.getContentAsString()).contains("yiban error");
    }

    @Test
    void commenceWithOtherExceptionShouldWriteDefaultErrorResponse() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException ex = new AuthenticationException("other error") {};

        entryPoint.commence(request, response, ex);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsString()).isNotEmpty();
    }

}
