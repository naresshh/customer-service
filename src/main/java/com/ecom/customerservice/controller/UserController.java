package com.ecom.customerservice.controller;


import com.ecom.customerservice.dto.CustomerDTO;
import com.ecom.customerservice.dto.UserRequestDTO;
import com.ecom.customerservice.modal.Role;
import com.ecom.customerservice.modal.User;
import com.ecom.customerservice.modal.UserRole;
import com.ecom.customerservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/api/users/")
@RequiredArgsConstructor
public class UserController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private  PasswordEncoder passwordEncoder;

    @PostMapping("/create")
    public ResponseEntity<?> createUser(@RequestBody UserRequestDTO userRequestDTO) {

        if (userRepository.existsByUsername(userRequestDTO.getUsername())) {
            return ResponseEntity.badRequest().body("Username already exists");
        }

        // Create a new User instance and set fields manually
        User user = new User();
        user.setUsername(userRequestDTO.getUsername());
        user.setPassword(passwordEncoder.encode(userRequestDTO.getPassword()));
        user.setEmail(userRequestDTO.getEmail());
        user.setEnabled(userRequestDTO.isEnabled());

        Set<UserRole> userRoles = new HashSet<>();

        for (String roleStr : userRequestDTO.getRoles()) {
            Role roleEnum;
            try {
                roleEnum = Role.valueOf(roleStr);
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().body("Invalid role: " + roleStr);
            }

            // Create UserRole instance and set fields manually
            UserRole userRole = new UserRole();
            userRole.setRole(roleEnum);
            userRole.setUser(user); // Associate this role with the user

            userRoles.add(userRole);
        }

        user.setRoles(userRoles);

        User savedUser = userRepository.save(user);

        return ResponseEntity.ok("User created successfully with ID: " + savedUser.getId());
    }

    @GetMapping("{id}")
    public CustomerDTO getCustomerById(@PathVariable Long id){

        User user = userRepository.getById(id);
        CustomerDTO customerDTO = new CustomerDTO();
        customerDTO.setId(user.getId());
        customerDTO.setEmail(user.getEmail());
        customerDTO.setName(user.getUsername());
        return customerDTO;
    }
}