package cn.yiban.open;

/**
 * Stub class for cn.yiban.open.Authorize (yiban SDK not available in public repos).
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class Authorize {

    public enum DISPLAY_TAG_T {
        WEB, MOBILE
    }

    private final String appKey;
    private final String appSecret;

    public Authorize(String appKey, String appSecret) {
        this.appKey = appKey;
        this.appSecret = appSecret;
    }

    public String forwardurl(String redirectUri, String state, DISPLAY_TAG_T display) {
        return "https://oauth.yiban.cn/code.html?client_id=" + appKey
                + "&redirect_uri=" + redirectUri
                + "&state=" + state
                + "&display=" + display.name().toLowerCase();
    }

    public String querytoken(String code, String redirectUri) {
        // Stub: in real SDK this exchanges code for token
        return "stub-token-for-" + code;
    }

}
