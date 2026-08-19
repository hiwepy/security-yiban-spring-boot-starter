package org.springframework.security.boot.yiban.endpoint;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import cn.yiban.open.Authorize;
import cn.yiban.open.Authorize.DISPLAY_TAG_T;


/**
 * <p>Yiban API Endpoint.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@RestController("/yiban/api/")
public class YibanApiEndpoint {
	
	private final Authorize authorize;
    private final String redirect_uri;
    private final String state;
    private final Authorize.DISPLAY_TAG_T display;
    
	/**
	 * Constructs a new yiban api endpoint instance.
	 *
	 * @param authorize the authorize
	 * @param redirect_uri the redirect_uri
	 * @param state the state
	 * @param display the display
	 */
	public YibanApiEndpoint(Authorize authorize, String redirect_uri, String state,
			DISPLAY_TAG_T display) {
		super();
		this.authorize = authorize;
		this.redirect_uri = redirect_uri;
		this.state = state;
		this.display = display;
	}
	 
	/**
	 * list.
	 *
	 * @return the result
	 * @throws Exception if an error occurs
	 */
	@GetMapping("login")
	public ResponseEntity<String> list() throws Exception {
		
		String url = authorize.forwardurl(redirect_uri, state, display); 
		return ResponseEntity.ok(url);
	}
	
}
