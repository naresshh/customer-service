package com.ecom.customerservice.dto;

import lombok.Data;

import java.util.Set;

@Data
public class UserRequestDTO {
    private String username;
    private String password;
    private String email;
    private boolean enabled;
    private Set<String> roles; // List of role names: ROLE_USER, ROLE_ADMIN etc.

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }
}