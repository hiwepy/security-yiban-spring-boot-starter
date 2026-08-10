package org.springframework.security.boot.yiban.authentication;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import cn.yiban.open.Authorize;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link YibanPreAuthenticatedProcessingFilter}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class YibanPreAuthenticatedProcessingFilterTest {

    @Test
    void constructorShouldSetFields() {
        Authorize authorize = new Authorize("key", "secret");
        YibanPreAuthenticatedProcessingFilter filter =
                new YibanPreAuthenticatedProcessingFilter(authorize, "http://localhost/callback", "QUERY", Authorize.DISPLAY_TAG_T.WEB);
        assertThat(filter).isNotNull();
    }

    @Test
    void doFilterShouldRedirect() throws IOException, ServletException {
        Authorize authorize = new Authorize("key", "secret");
        YibanPreAuthenticatedProcessingFilter filter =
                new YibanPreAuthenticatedProcessingFilter(authorize, "http://localhost/callback", "QUERY", Authorize.DISPLAY_TAG_T.WEB);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (req, res) -> {});

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_MOVED_TEMPORARILY);
        assertThat(response.getRedirectedUrl()).contains("key");
    }

    @Test
    void getPreAuthenticatedPrincipalShouldReturnNA() {
        Authorize authorize = new Authorize("key", "secret");
        YibanPreAuthenticatedProcessingFilter filter =
                new YibanPreAuthenticatedProcessingFilter(authorize, "http://localhost/callback", "QUERY", Authorize.DISPLAY_TAG_T.WEB);
        // Use reflection to call the protected method
        try {
            var method = YibanPreAuthenticatedProcessingFilter.class.getDeclaredMethod("getPreAuthenticatedPrincipal", jakarta.servlet.http.HttpServletRequest.class);
            method.setAccessible(true);
            Object result = method.invoke(filter, new MockHttpServletRequest());
            assertThat(result).isEqualTo("N/A");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void getPreAuthenticatedCredentialsShouldReturnNA() {
        Authorize authorize = new Authorize("key", "secret");
        YibanPreAuthenticatedProcessingFilter filter =
                new YibanPreAuthenticatedProcessingFilter(authorize, "http://localhost/callback", "QUERY", Authorize.DISPLAY_TAG_T.WEB);
        try {
            var method = YibanPreAuthenticatedProcessingFilter.class.getDeclaredMethod("getPreAuthenticatedCredentials", jakarta.servlet.http.HttpServletRequest.class);
            method.setAccessible(true);
            Object result = method.invoke(filter, new MockHttpServletRequest());
            assertThat(result).isEqualTo("N/A");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
