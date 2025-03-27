package com.ecom.customerservice.controller;

import com.ecom.customerservice.modal.User;
import com.ecom.customerservice.repository.UserRepository;
import com.ecom.customerservice.security.JwtUtils;
import com.ecom.customerservice.security.LoginRequest;
import com.ecom.customerservice.security.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@CrossOrigin(origins = "http://localhost:3000")
public class AuthController {

    private final JwtUtils jwtUtils;
    @Autowired
    public AuthController(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
            System.out.println("Raw password received: " + loginRequest.getPassword());
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.UNAUTHORIZED);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

     User user = userRepository.findByUsername(userDetails.getUsername()).get();

        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwtToken,user.getId());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/validate-admin")
    public ResponseEntity<Boolean> validateAdmin(@RequestHeader("Authorization") String token) {
        // Extract JWT token
        String jwtToken = token.replace("Bearer ", "");

        // Get authentication from Security Context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Check if user has ROLE_ADMIN
        if (authentication == null || authentication.getAuthorities().stream()
                .noneMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"))) {
            return ResponseEntity.ok(false); // Not an admin
        }

        return ResponseEntity.ok(true); // Admin user
    }

}