package cn.yiban.open.common;

/**
 * Stub class for cn.yiban.open.common.User (yiban SDK not available in public repos).
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class User {

    private final String token;

    /**
     * Constructs a new user instance.
     *
     * @param token the token
     */
    public User(String token) {
        this.token = token;
    }

    /**
     * Get real-name info of the current user.
     * @return JSON string with user info
     */
    public String realme() {
        return "{\"status\":\"success\",\"info\":{"
                + "\"yb_userid\":\"1\","
                + "\"yb_username\":\"testuser\","
                + "\"yb_usernick\":\"Test User\","
                + "\"yb_sex\":\"0\","
                + "\"yb_money\":\"0\","
                + "\"yb_exp\":\"0\","
                + "\"yb_userhead\":\"\","
                + "\"yb_schoolid\":\"0\","
                + "\"yb_schoolname\":\"Test School\","
                + "\"yb_realname\":\"Test\","
                + "\"yb_birthday\":\"2000-01-01\","
                + "\"yb_studentid\":\"0\","
                + "\"yb_identity\":\"student\""
                + "}}";
    }

}
