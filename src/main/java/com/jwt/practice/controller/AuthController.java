package com.jwt.practice.controller;


import java.util.Arrays;
import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.practice.util.JwtUtil;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api")
public class AuthController {

    @PostMapping("/login_CookieResponse")
    public ResponseEntity<String> login(@RequestParam String username,
                                        @RequestParam String password,
                                        @RequestParam String role,
                                        HttpServletResponse response) {
        // Hardcoded credentials
        if ("lavanya".equals(username) && "1234".equals(password) && "USER".equals(role)) {
            String token = JwtUtil.generateToken(username, role);

            // Store JWT in cookie
            Cookie cookie = new Cookie("jwt", token);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            response.addCookie(cookie);

            return ResponseEntity.ok("Login successful! JWT stored in cookie.");
        }
        return ResponseEntity.status(401).body("Invalid credentials");
    }
 
    @PostMapping("/login_ResponseBody")
    //Login (Send JWT in body, not in cookie)
    //Server generates JWT as a plain string and sends it in the response body (not in a cookie).
    //Client takes that JWT string and stores it in a cookie manually (in browser or app).
    
    public ResponseEntity<String> login(@RequestParam String username,
                                        @RequestParam String password,
                                        @RequestParam String role) {
        if ("lavanya".equals(username) && "807395".equals(password) && "admin".equals(role)) {
            String token = JwtUtil.generateToken(username, role);
            return ResponseEntity.ok(token); // Send token as response body
        }
        return ResponseEntity.status(401).body("Invalid credentials");
    }

    @GetMapping("/secure-data")
    //Secure Endpoint (Read JWT from cookie)
    
    public ResponseEntity<String> secureData(@CookieValue(name = "jwt", required = false) String token) {
        if (token != null && JwtUtil.validateToken(token)) {
            String username = JwtUtil.getUsername(token);
            return ResponseEntity.ok("Hello " + username + "! This is protected data.");
        }
        return ResponseEntity.status(401).body("Unauthorized - Invalid or missing token");
        
    }
    
    
    @GetMapping("/homepage")
    public ResponseEntity<String> homepage(HttpServletRequest request) {
        String token = JwtUtil.getTokenFromCookies(request);

        if (token != null && JwtUtil.validateToken(token)) {
            String username = JwtUtil.getUsername(token);
            return ResponseEntity.ok("Welcome to the Homepage, " + username + "!");
        }
        return ResponseEntity.status(401).body("Unauthorized - Please log in first.");
    }

    @GetMapping("/homepage_jwt_roleBasedAuth")
    public ResponseEntity<String> homepage() {
        String username = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String role = SecurityContextHolder.getContext().getAuthentication()
                        .getAuthorities().iterator().next().getAuthority();

        return ResponseEntity.ok("Welcome " + username + "! Your role is " + role);
    }

    
    @GetMapping("/list")
    public ResponseEntity<?> getProducts() {
        List<String> allProducts = Arrays.asList("Laptop", "Mobile", "Headphones", "Camera");
        List<String> userProducts = Arrays.asList("Laptop", "Mobile");

        // Role comes from SecurityContext
        String role = SecurityContextHolder.getContext().getAuthentication()
                         .getAuthorities().iterator().next().getAuthority();

        if ("ROLE_ADMIN".equals(role)) {
            return ResponseEntity.ok(allProducts);
        } else {
            return ResponseEntity.ok(userProducts);
        }
    }
 
    
    
}
