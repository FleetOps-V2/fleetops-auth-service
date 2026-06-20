package com.fleetops.auth.dto;

public class AuthResponse {
    private String username;
    private String role;

    public AuthResponse(String username, String role) {
        this.username = username;
        this.role = role;
    }

    public String getUsername() { return username; }
    public String getRole() { return role; }
}
