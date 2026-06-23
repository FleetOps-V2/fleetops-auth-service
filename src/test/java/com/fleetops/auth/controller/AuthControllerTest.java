package com.fleetops.auth.controller;

import com.fleetops.auth.dto.AuthResponse;
import com.fleetops.auth.dto.LoginRequest;
import com.fleetops.auth.dto.RegisterRequest;
import com.fleetops.auth.entity.Role;
import com.fleetops.auth.entity.User;
import com.fleetops.auth.repository.UserRepository;
import com.fleetops.auth.security.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock AuthenticationManager authenticationManager;
    @Mock UserRepository userRepository;
    @Mock PasswordEncoder passwordEncoder;
    @Mock JwtUtils jwtUtils;

    @InjectMocks AuthController controller;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(controller, "jwtExpirationMs", 86400000L);
        ReflectionTestUtils.setField(controller, "cookieSecure", false);
    }

    @Test
    void login_setsHttpOnlyCookieAndReturnsUsernameAndRole() {
        UserDetails userDetails = mock(UserDetails.class);
        when(userDetails.getUsername()).thenReturn("admin1");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(userDetails);
        when(authenticationManager.authenticate(any())).thenReturn(auth);

        User user = new User();
        user.setUsername("admin1");
        user.setRole(Role.ADMIN);
        when(userRepository.findByUsername("admin1")).thenReturn(Optional.of(user));
        when(jwtUtils.generateToken(any(), eq("ADMIN"))).thenReturn("test-jwt");

        MockHttpServletResponse response = new MockHttpServletResponse();
        LoginRequest request = new LoginRequest();
        request.setUsername("admin1");
        request.setPassword("Admin@123");

        ResponseEntity<?> result = controller.login(request, response);

        assertEquals(200, result.getStatusCode().value());
        String setCookie = response.getHeader(HttpHeaders.SET_COOKIE);
        assertNotNull(setCookie);
        assertTrue(setCookie.contains("jwt=test-jwt"), "Cookie must contain JWT value");
        assertTrue(setCookie.contains("HttpOnly"), "Cookie must be HttpOnly");
        AuthResponse body = (AuthResponse) result.getBody();
        assertNotNull(body);
        assertEquals("admin1", body.getUsername());
        assertEquals("ADMIN", body.getRole());
    }

    @Test
    void login_returnsTokenInBody() {
        UserDetails userDetails = mock(UserDetails.class);
        when(userDetails.getUsername()).thenReturn("driver1");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(userDetails);
        when(authenticationManager.authenticate(any())).thenReturn(auth);

        User user = new User();
        user.setUsername("driver1");
        user.setRole(Role.DRIVER);
        when(userRepository.findByUsername("driver1")).thenReturn(Optional.of(user));
        when(jwtUtils.generateToken(any(), eq("DRIVER"))).thenReturn("some-token");

        MockHttpServletResponse response = new MockHttpServletResponse();
        LoginRequest request = new LoginRequest();
        request.setUsername("driver1");
        request.setPassword("Driver@123");

        ResponseEntity<?> result = controller.login(request, response);

        AuthResponse body = (AuthResponse) result.getBody();
        assertNotNull(body);
        assertEquals("driver1", body.getUsername());
        assertEquals("DRIVER", body.getRole());
        assertEquals("some-token", body.getToken());
    }

    @Test
    void logout_setsExpiredCookie() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        ResponseEntity<?> result = controller.logout(response);

        assertEquals(200, result.getStatusCode().value());
        String setCookie = response.getHeader(HttpHeaders.SET_COOKIE);
        assertNotNull(setCookie);
        assertTrue(setCookie.contains("Max-Age=0"), "Logout must expire the cookie");
        assertTrue(setCookie.contains("HttpOnly"));
    }

    @Test
    void register_returnsOkWhenCredentialsAvailable() {
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("new@test.com")).thenReturn(false);
        when(passwordEncoder.encode("Pass@1234")).thenReturn("encoded");

        RegisterRequest request = new RegisterRequest();
        request.setUsername("newuser");
        request.setEmail("new@test.com");
        request.setPassword("Pass@1234");

        ResponseEntity<?> result = controller.register(request);

        assertEquals(200, result.getStatusCode().value());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void register_returnsBadRequestWhenUsernameExists() {
        when(userRepository.existsByUsername("existing")).thenReturn(true);

        RegisterRequest request = new RegisterRequest();
        request.setUsername("existing");
        request.setEmail("e@test.com");
        request.setPassword("Pass@1234");

        ResponseEntity<?> result = controller.register(request);

        assertEquals(400, result.getStatusCode().value());
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_returnsBadRequestWhenEmailExists() {
        when(userRepository.existsByUsername("newuser2")).thenReturn(false);
        when(userRepository.existsByEmail("taken@test.com")).thenReturn(true);

        RegisterRequest request = new RegisterRequest();
        request.setUsername("newuser2");
        request.setEmail("taken@test.com");
        request.setPassword("Pass@1234");

        ResponseEntity<?> result = controller.register(request);

        assertEquals(400, result.getStatusCode().value());
        verify(userRepository, never()).save(any());
    }

    @Test
    void getCurrentUser_returnsUserInfo() {
        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn("manager1");

        User user = new User();
        user.setUsername("manager1");
        user.setEmail("manager@fleet.com");
        user.setRole(Role.MANAGER);
        when(userRepository.findByUsername("manager1")).thenReturn(Optional.of(user));

        ResponseEntity<?> result = controller.getCurrentUser(auth);

        assertEquals(200, result.getStatusCode().value());
    }

    @Test
    void getCurrentUser_returns401WhenNotAuthenticated() {
        ResponseEntity<?> result = controller.getCurrentUser(null);
        assertEquals(401, result.getStatusCode().value());
    }
}
