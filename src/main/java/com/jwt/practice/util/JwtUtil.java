   
	package com.jwt.practice.util;

	import java.security.Key;
import java.util.Date;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

	public class JwtUtil {
		
		

	    // Use a constant secret key (must be at least 32 characters for HS256)
	  //  private static final String SECRET = "mysecretkeyformyjwt8073951234567890";
	  //  private static final Key key = Keys.hmacShaKeyFor(SECRET.getBytes());
        
	    private static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
	    
	    // able to generate token , can save in string and cookie.
	    // But validation failing when we pass manually string token to call api 
	    // successful validation happens when we extract token from cookie like automatically 
	    
	    private static final long EXPIRATION_TIME = 1000 * 60 * 30; // 5 minutes

	    
	    
	    public static String generateToken(String username, String role) {
	        return Jwts.builder()
	                .setSubject(username)
	                .claim("role", role)
	                .setIssuedAt(new Date())
	                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
	                .signWith(key, SignatureAlgorithm.HS256)
	                .compact();
	    }

	    public static boolean validateToken(String token) {
	        try {
	            Jwts.parserBuilder()
	                .setSigningKey(key) // Always same key for parsing
	                .build()
	                .parseClaimsJws(token);
	            return true;
	        } catch (Exception e) {
	            System.out.println("Token validation failed: " + e.getMessage());
	            return false;
	        }
	    }

	    public static String getUsername(String token) {
	        return Jwts.parserBuilder()
	                .setSigningKey(key)
	                .build()
	                .parseClaimsJws(token)
	                .getBody()
	                .getSubject();
	    }
	    
	 // New helper to get token from cookie
	    public static String getTokenFromCookies(HttpServletRequest request) {
	        if (request.getCookies() != null) {
	            for (Cookie cookie : request.getCookies()) {
	                if ("jwt".equals(cookie.getName())) {
	                    return cookie.getValue();
	                }
	            }
	        }
	        return null;
	    }
	    
	    public static String getUserRole(String token) {
	        return Jwts.parserBuilder()
	                .setSigningKey(key)
	                .build()
	                .parseClaimsJws(token)
	                .getBody()
	                .get("role", String.class);
	    }

	}
	
	
	