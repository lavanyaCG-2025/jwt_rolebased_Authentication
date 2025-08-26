
package com.jwt.practice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    @GetMapping("/list")
    public ResponseEntity<?> getProducts() {
        List<String> allProducts = Arrays.asList("Laptop", "Mobile", "Headphones", "Camera");
        List<String> userProducts = Arrays.asList("Laptop", "Mobile");

        String role = SecurityContextHolder.getContext().getAuthentication()
                        .getAuthorities().iterator().next().getAuthority();

        if ("ROLE_ADMIN".equals(role)) {
            return ResponseEntity.ok(allProducts);
        } else {
            return ResponseEntity.ok(userProducts);
        }
    }
}

