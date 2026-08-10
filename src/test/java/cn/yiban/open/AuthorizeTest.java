package cn.yiban.open;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for the Authorize stub class.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class AuthorizeTest {

    @Test
    void constructorShouldSetAppKeyAndSecret() {
        Authorize authorize = new Authorize("app-key", "app-secret");
        assertThat(authorize).isNotNull();
    }

    @Test
    void forwardurlShouldReturnUrlWithParameters() {
        Authorize authorize = new Authorize("app-key", "app-secret");
        String url = authorize.forwardurl("http://localhost/callback", "QUERY", Authorize.DISPLAY_TAG_T.WEB);
        assertThat(url).contains("app-key");
        assertThat(url).contains("localhost");
        assertThat(url).contains("QUERY");
    }

    @Test
    void querytokenShouldReturnToken() {
        Authorize authorize = new Authorize("app-key", "app-secret");
        String token = authorize.querytoken("auth-code", "");
        assertThat(token).contains("stub-token");
    }

    @Test
    void displayTagValuesShouldExist() {
        assertThat(Authorize.DISPLAY_TAG_T.WEB).isNotNull();
        assertThat(Authorize.DISPLAY_TAG_T.MOBILE).isNotNull();
    }

}
