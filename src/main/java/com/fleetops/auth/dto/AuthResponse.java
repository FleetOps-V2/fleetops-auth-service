package com.fleetops.auth.dto;

public class AuthResponse {
    private String username;
    private String role;
    private String token;

    public AuthResponse(String username, String role, String token) {
        this.username = username;
        this.role = role;
        this.token = token;
    }

    public String getUsername() { return username; }
    public String getRole() { return role; }
    public String getToken() { return token; }
}
