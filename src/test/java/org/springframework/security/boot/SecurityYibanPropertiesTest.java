package org.springframework.security.boot;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link SecurityYibanProperties}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class SecurityYibanPropertiesTest {

    @Test
    void defaultValuesShouldBeCorrect() {
        SecurityYibanProperties props = new SecurityYibanProperties();
        assertThat(props.isEnabled()).isFalse();
    }

    @Test
    void prefixShouldBeCorrect() {
        assertThat(SecurityYibanProperties.PREFIX).isEqualTo("spring.security.yiban");
    }

    @Test
    void enabledSetterShouldWork() {
        SecurityYibanProperties props = new SecurityYibanProperties();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
    }

}
