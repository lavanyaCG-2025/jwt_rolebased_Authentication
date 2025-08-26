package com.jwt.practice.security;

import com.jwt.practice.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class JwtAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = JwtUtil.getTokenFromCookies(request);

        if (token != null && JwtUtil.validateToken(token)) {
            String username = JwtUtil.getUsername(token);
            String role = JwtUtil.getUserRole(token);

            // Block DISABLED users globally
            if ("DISABLED".equalsIgnoreCase(role)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().write("NO ACCESS for disabled users.");
                return;
            }

            // Attach authentication to SecurityContext
            SimpleGrantedAuthority authority =
                    new SimpleGrantedAuthority("ROLE_" + role.toUpperCase());
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(username, null, Collections.singletonList(authority));

            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        filterChain.doFilter(request, response);
    }
}
