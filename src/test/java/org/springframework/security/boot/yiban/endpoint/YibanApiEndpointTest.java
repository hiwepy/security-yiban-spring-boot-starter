package org.springframework.security.boot.yiban.endpoint;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import cn.yiban.open.Authorize;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link YibanApiEndpoint}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class YibanApiEndpointTest {

    @Test
    void listShouldReturnAuthorizationUrl() throws Exception {
        Authorize authorize = new Authorize("test-key", "test-secret");
        YibanApiEndpoint endpoint = new YibanApiEndpoint(authorize, "http://localhost/callback", "QUERY", Authorize.DISPLAY_TAG_T.WEB);

        ResponseEntity<String> response = endpoint.list();

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("test-key");
        assertThat(response.getBody()).contains("localhost");
    }

}
