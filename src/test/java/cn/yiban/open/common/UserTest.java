package cn.yiban.open.common;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for the User stub class.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class UserTest {

    @Test
    void constructorShouldSetToken() {
        User user = new User("test-token");
        assertThat(user).isNotNull();
    }

    @Test
    void realmeShouldReturnJsonString() {
        User user = new User("test-token");
        String result = user.realme();
        assertThat(result).contains("success");
        assertThat(result).contains("yb_userid");
        assertThat(result).contains("yb_username");
    }

}
