package org.springframework.security.boot.yiban.exception;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AuthenticationYibanServerException}.
 * @author [@Loong Wan](https://github.com/loong10k)
 */
class AuthenticationYibanServerExceptionTest {

    @Test
    void constructorWithCodeAndMessageShouldSetFields() {
        AuthenticationYibanServerException ex = new AuthenticationYibanServerException("E001", "test error");
        assertThat(ex.getYibanCode()).isEqualTo("E001");
        assertThat(ex.getMessage()).isEqualTo("test error");
        assertThat(ex.getCode()).isNotNull();
    }

    @Test
    void constructorWithCodeMessageAndCauseShouldSetFields() {
        Throwable cause = new RuntimeException("root cause");
        AuthenticationYibanServerException ex = new AuthenticationYibanServerException("E002", "test error", cause);
        assertThat(ex.getYibanCode()).isEqualTo("E002");
        assertThat(ex.getMessage()).isEqualTo("test error");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

}
