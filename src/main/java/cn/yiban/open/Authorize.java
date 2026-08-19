package cn.yiban.open;

/**
 * Stub class for cn.yiban.open.Authorize (yiban SDK not available in public repos).
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class Authorize {

    public enum DISPLAY_TAG_T {
        WEB, MOBILE
    }

    private final String appKey;
    private final String appSecret;

    /**
     * Constructs a new authorize instance.
     *
     * @param appKey the app key
     * @param appSecret the app secret
     */
    public Authorize(String appKey, String appSecret) {
        this.appKey = appKey;
        this.appSecret = appSecret;
    }

    /**
     * forwardurl.
     *
     * @param redirectUri the redirect uri
     * @param state the state
     * @param display the display
     * @return the result
     */
    public String forwardurl(String redirectUri, String state, DISPLAY_TAG_T display) {
        return "https://oauth.yiban.cn/code.html?client_id=" + appKey
                + "&redirect_uri=" + redirectUri
                + "&state=" + state
                + "&display=" + display.name().toLowerCase();
    }

    /**
     * querytoken.
     *
     * @param code the code
     * @param redirectUri the redirect uri
     * @return the result
     */
    public String querytoken(String code, String redirectUri) {
        // Stub: in real SDK this exchanges code for token
        return "stub-token-for-" + code;
    }

}
