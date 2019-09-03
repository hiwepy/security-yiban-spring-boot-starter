package org.springframework.security.boot.yiban.endpoint;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import cn.yiban.open.Authorize;
import cn.yiban.open.Authorize.DISPLAY_TAG_T;


@RestController("/yiban/api/")
public class YibanApiEndpoint {
	
	private final Authorize authorize;
    private final String redirect_uri;
    private final String state;
    private final Authorize.DISPLAY_TAG_T display;
    
	public YibanApiEndpoint(Authorize authorize, String redirect_uri, String state,
			DISPLAY_TAG_T display) {
		super();
		this.authorize = authorize;
		this.redirect_uri = redirect_uri;
		this.state = state;
		this.display = display;
	}
	 
	@GetMapping("login")
	public ResponseEntity<String> list() throws Exception {
		
		String url = authorize.forwardurl(redirect_uri, state, display); 
		return ResponseEntity.ok(url);
	}
	
}
