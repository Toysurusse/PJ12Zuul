package com.eureka.zuul.security;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.eureka.zuul.security.JwtConfig;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JwtTokenAuthenticationFilter extends  OncePerRequestFilter {
    
	private final JwtConfig jwtConfig;

	private static final Logger logger = LoggerFactory.getLogger(JwtTokenAuthenticationFilter.class);

	public JwtTokenAuthenticationFilter(JwtConfig jwtConfig) {
		this.jwtConfig = jwtConfig;
	}

	@Autowired
	private JwtProvider tokenProvider;

	@Value("JwtSecretKey")
	private String jwtSecret;

	@Value("86400000")
	private int jwtExpiration;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		// 1. get the authentication header. Tokens are supposed to be passed in the authentication header
		String header = request.getHeader(jwtConfig.getHeader());
		
		// 2. validate the header and check the prefix
		if(header == null || !header.startsWith(jwtConfig.getPrefix())) {
			chain.doFilter(request, response);  		// If not valid, go to the next filter.
			return;
		}
		
		// If there is no token provided and hence the user won't be authenticated. 
		// It's Ok. Maybe the user accessing a public path or asking for a token.
		
		// All secured paths that needs a token are already defined and secured in config class.
		// And If user tried to access without access token, then he won't be authenticated and an exception will be thrown.
		
		// 3. Get the token
		String token = header.replace(jwtConfig.getPrefix(), "");
		try {
			String jwt = getJwt(request);
			logger.info(request.getRequestURI());
			logger.info(request.getRequestURI()+"  token : "+jwt);
			Claims claims = Jwts.parser()
					.setSigningKey("JwtSecretKey")
					.parseClaimsJws(token)
					.getBody();
			String username = claims.getSubject();
			logger.info(username);
			if(username != null) {
				@SuppressWarnings("unchecked")
				List<String> authorities = (List<String>) claims.get("authorities");
				logger.info("Autoritées : "+authorities);
				// 5. Create auth object
				// UsernamePasswordAuthenticationToken: A built-in object, used by spring to represent the current authenticated / being authenticated user.
				// It needs a list of authorities, which has type of GrantedAuthority interface, where SimpleGrantedAuthority is an implementation of that interface
				UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
						username, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
				// 6. Authenticate the user
				// Now, user is authenticated
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
		} catch (Exception e) {
			logger.error("Can NOT set user authentication -> Message: {}", e);
		}

		// go to the next filter in the filter chain
		chain.doFilter(request, response);
	}
	private String getJwt(HttpServletRequest request) {
		String authHeader = request.getHeader("Authorization");

		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			return authHeader.replace("Bearer ", "");
		}

		return null;
	}
}